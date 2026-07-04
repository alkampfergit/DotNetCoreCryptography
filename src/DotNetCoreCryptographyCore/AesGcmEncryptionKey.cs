using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Symmetric key based on AES-256-GCM authenticated encryption (AEAD). This is
    /// the default key type since format v2: every chunk of the stream carries a
    /// 16-byte authentication tag, so any tampering, truncation or reordering of
    /// the ciphertext makes decryption fail with <see cref="CryptographicException"/>.
    /// </summary>
    /// <remarks>
    /// <para>Stream format (STREAM-style chunked AEAD, current version):</para>
    /// <code>
    /// [ 4-byte magic ][ 32-byte random salt ]
    /// [ chunk 0 ][ chunk 1 ] ... [ final chunk ]
    ///
    /// subkey  := HKDF-SHA256(ikm = key, salt = salt, info = "DotNetCoreCryptography/AesGcm/v1")
    /// chunk   := [ 4-byte big-endian header ][ ciphertext ][ 16-byte tag ]
    /// header  := plaintext length (64 KiB except final chunk) | 0x80000000 on final chunk
    /// nonce_i := 0x00 * 7 (zero prefix) || 32-bit big-endian chunk counter || final-flag byte  (12 bytes total)
    /// </code>
    /// <para>
    /// Each <see cref="Encrypt(Stream, Stream, byte[])"/> derives a fresh AES-256
    /// subkey from the long-term key and a 256-bit random salt, so the same
    /// long-term key can encrypt an effectively unbounded number of messages: the
    /// subkeys (and therefore the deterministic per-chunk nonces) do not collide
    /// even across ~2^64 messages. The per-chunk counter defeats chunk reordering,
    /// the final flag defeats truncation, and the optional associated data is
    /// authenticated together with the first chunk. Note that decryption writes
    /// each chunk to the destination as soon as that chunk is authenticated; if a
    /// later chunk fails, the destination contains an authenticated prefix of the
    /// plaintext and the operation throws.
    /// </para>
    /// <para>
    /// Legacy streams written by earlier versions (no leading magic; a 7-byte
    /// random nonce prefix followed directly by the chunks, encrypted with the
    /// long-term key) are still decrypted for backward compatibility.
    /// </para>
    /// </remarks>
    public sealed class AesGcmEncryptionKey : EncryptionKey
    {
        private const int KeySizeInBytes = 32;
        private const int ChunkSize = 64 * 1024;
        private const int NoncePrefixSize = 7;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int SaltSize = 32;
        private const uint FinalChunkFlag = 0x8000_0000u;

        /// <summary>
        /// "DNC" + 0x10: marks the subkey-derivation stream format. A legacy stream
        /// begins with a random 7-byte nonce prefix, so it matches this magic only
        /// with probability 2^-32; a false match simply fails authentication, so the
        /// scheme stays fail-closed.
        /// </summary>
        private static readonly byte[] GcmStreamMagic = { 0x44, 0x4E, 0x43, 0x10 };

        /// <summary>Domain-separation label for the per-stream HKDF derivation.</summary>
        private static readonly byte[] HkdfInfo =
            System.Text.Encoding.ASCII.GetBytes("DotNetCoreCryptography/AesGcm/v1");

        private readonly byte[] _key;

        /// <summary>
        /// Create a new random AES-256-GCM key.
        /// </summary>
        public AesGcmEncryptionKey()
        {
            _key = RandomNumberGenerator.GetBytes(KeySizeInBytes);
        }

        public AesGcmEncryptionKey(byte[] serializedValue)
        {
            ArgumentNullException.ThrowIfNull(serializedValue);
            if (serializedValue.Length != KeySizeInBytes + 1
                || serializedValue[0] != (byte)KeyType.Aes256Gcm)
            {
                throw new CryptographicException("Serialized key is not a valid AES-256-GCM key");
            }
            _key = serializedValue[1..];
        }

        /// <summary>
        /// Creates a key from raw key material (e.g. derived from a password with
        /// PBKDF2). The input is copied, so the caller can zero its own buffer.
        /// </summary>
        internal AesGcmEncryptionKey(ReadOnlySpan<byte> rawKey)
        {
            if (rawKey.Length != KeySizeInBytes)
            {
                throw new CryptographicException("Raw AES-256-GCM key material must be 32 bytes");
            }
            _key = rawKey.ToArray();
        }

        public override byte[] Serialize()
        {
            var serialized = new byte[KeySizeInBytes + 1];
            serialized[0] = (byte)KeyType.Aes256Gcm;
            _key.CopyTo(serialized, 1);
            return serialized;
        }

        internal override byte[] ExportRawKeyMaterial()
        {
            return (byte[])_key.Clone();
        }

        public override void Encrypt(Stream sourceStream, Stream destinationStream, byte[] associatedData = null)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var subkey = DeriveSubkey(salt);
            try
            {
                using var gcm = new AesGcm(subkey, TagSize);
                // Deterministic all-zero nonce prefix: uniqueness is guaranteed by the
                // per-stream subkey, not by the prefix.
                var state = EncryptionState.Create();
                destinationStream.Write(GcmStreamMagic, 0, GcmStreamMagic.Length);
                destinationStream.Write(salt, 0, salt.Length);

                state.CurrentLength = FillChunk(sourceStream, state.Current);
                while (true)
                {
                    int nextLength = FillChunk(sourceStream, state.Next);
                    bool isFinal = nextLength == 0;
                    SealCurrentChunk(gcm, state, isFinal, associatedData);
                    destinationStream.Write(state.Header, 0, state.Header.Length);
                    destinationStream.Write(state.Cipher, 0, state.CurrentLength);
                    destinationStream.Write(state.Tag, 0, state.Tag.Length);
                    if (isFinal)
                    {
                        break;
                    }
                    state.MoveNext(nextLength);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(subkey);
            }
        }

        public override async Task EncryptAsync(Stream sourceStream, Stream destinationStream, byte[] associatedData = null)
        {
            var salt = RandomNumberGenerator.GetBytes(SaltSize);
            var subkey = DeriveSubkey(salt);
            try
            {
                using var gcm = new AesGcm(subkey, TagSize);
                var state = EncryptionState.Create();
                await destinationStream.WriteAsync(GcmStreamMagic).ConfigureAwait(false);
                await destinationStream.WriteAsync(salt).ConfigureAwait(false);

                state.CurrentLength = await FillChunkAsync(sourceStream, state.Current).ConfigureAwait(false);
                while (true)
                {
                    int nextLength = await FillChunkAsync(sourceStream, state.Next).ConfigureAwait(false);
                    bool isFinal = nextLength == 0;
                    SealCurrentChunk(gcm, state, isFinal, associatedData);
                    await destinationStream.WriteAsync(state.Header).ConfigureAwait(false);
                    await destinationStream.WriteAsync(state.Cipher.AsMemory(0, state.CurrentLength)).ConfigureAwait(false);
                    await destinationStream.WriteAsync(state.Tag).ConfigureAwait(false);
                    if (isFinal)
                    {
                        break;
                    }
                    state.MoveNext(nextLength);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(subkey);
            }
        }

        private byte[] DeriveSubkey(ReadOnlySpan<byte> salt)
        {
            var subkey = new byte[KeySizeInBytes];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, _key, subkey, salt, HkdfInfo);
            return subkey;
        }

        public override void Decrypt(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null)
        {
            try
            {
                var state = DecryptionState.Create();
                var lead = new byte[GcmStreamMagic.Length];
                encryptedStream.ReadExactly(lead);

                if (lead.AsSpan().SequenceEqual(GcmStreamMagic))
                {
                    var salt = new byte[SaltSize];
                    encryptedStream.ReadExactly(salt);
                    var subkey = DeriveSubkey(salt);
                    try
                    {
                        using var gcm = new AesGcm(subkey, TagSize);
                        DecryptChunks(gcm, encryptedStream, destinationStream, state, associatedData);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(subkey);
                    }
                }
                else
                {
                    // Legacy stream: the bytes just read are the first part of the
                    // 7-byte random nonce prefix; read the remainder and decrypt with
                    // the long-term key.
                    lead.CopyTo(state.Nonce, 0);
                    encryptedStream.ReadExactly(state.Nonce.AsSpan(GcmStreamMagic.Length, NoncePrefixSize - GcmStreamMagic.Length));
                    using var gcm = new AesGcm(_key, TagSize);
                    DecryptChunks(gcm, encryptedStream, destinationStream, state, associatedData);
                }
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }

        public override async Task DecryptAsync(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null)
        {
            try
            {
                var state = DecryptionState.Create();
                var lead = new byte[GcmStreamMagic.Length];
                await encryptedStream.ReadExactlyAsync(lead).ConfigureAwait(false);

                if (lead.AsSpan().SequenceEqual(GcmStreamMagic))
                {
                    var salt = new byte[SaltSize];
                    await encryptedStream.ReadExactlyAsync(salt).ConfigureAwait(false);
                    var subkey = DeriveSubkey(salt);
                    try
                    {
                        using var gcm = new AesGcm(subkey, TagSize);
                        await DecryptChunksAsync(gcm, encryptedStream, destinationStream, state, associatedData).ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(subkey);
                    }
                }
                else
                {
                    lead.CopyTo(state.Nonce, 0);
                    await encryptedStream.ReadExactlyAsync(state.Nonce.AsMemory(GcmStreamMagic.Length, NoncePrefixSize - GcmStreamMagic.Length)).ConfigureAwait(false);
                    using var gcm = new AesGcm(_key, TagSize);
                    await DecryptChunksAsync(gcm, encryptedStream, destinationStream, state, associatedData).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }

        private static void DecryptChunks(AesGcm gcm, Stream encryptedStream, Stream destinationStream, DecryptionState state, byte[] associatedData)
        {
            bool isFinal = false;
            while (!isFinal)
            {
                encryptedStream.ReadExactly(state.Header);
                int length = ParseChunkHeader(state, out isFinal);
                encryptedStream.ReadExactly(state.Cipher.AsSpan(0, length));
                encryptedStream.ReadExactly(state.Tag);
                OpenChunk(gcm, state, length, isFinal, associatedData);
                destinationStream.Write(state.Plain, 0, length);
                state.Counter = IncrementCounter(state.Counter);
            }

            if (encryptedStream.ReadByte() != -1)
            {
                throw new CryptographicException("Unexpected data after the final chunk");
            }
        }

        private static async Task DecryptChunksAsync(AesGcm gcm, Stream encryptedStream, Stream destinationStream, DecryptionState state, byte[] associatedData)
        {
            bool isFinal = false;
            while (!isFinal)
            {
                await encryptedStream.ReadExactlyAsync(state.Header).ConfigureAwait(false);
                int length = ParseChunkHeader(state, out isFinal);
                await encryptedStream.ReadExactlyAsync(state.Cipher.AsMemory(0, length)).ConfigureAwait(false);
                await encryptedStream.ReadExactlyAsync(state.Tag).ConfigureAwait(false);
                OpenChunk(gcm, state, length, isFinal, associatedData);
                await destinationStream.WriteAsync(state.Plain.AsMemory(0, length)).ConfigureAwait(false);
                state.Counter = IncrementCounter(state.Counter);
            }

            if (encryptedStream.ReadByte() != -1)
            {
                throw new CryptographicException("Unexpected data after the final chunk");
            }
        }

        private static void SealCurrentChunk(AesGcm gcm, EncryptionState state, bool isFinal, byte[] associatedData)
        {
            FillNonce(state.Nonce, state.Counter, isFinal);
            BinaryPrimitives.WriteUInt32BigEndian(
                state.Header,
                (uint)state.CurrentLength | (isFinal ? FinalChunkFlag : 0));
            gcm.Encrypt(
                state.Nonce,
                state.Current.AsSpan(0, state.CurrentLength),
                state.Cipher.AsSpan(0, state.CurrentLength),
                state.Tag,
                AssociatedDataForChunk(state.Counter, associatedData));
        }

        private static int ParseChunkHeader(DecryptionState state, out bool isFinal)
        {
            var headerValue = BinaryPrimitives.ReadUInt32BigEndian(state.Header);
            isFinal = (headerValue & FinalChunkFlag) != 0;
            int length = (int)(headerValue & ~FinalChunkFlag);
            // Non-final chunks are always written full-size; the length check also
            // bounds what is read into the fixed-size buffers.
            if (length > ChunkSize || (!isFinal && length != ChunkSize))
            {
                throw new CryptographicException("Invalid chunk header");
            }
            return length;
        }

        private static void OpenChunk(AesGcm gcm, DecryptionState state, int length, bool isFinal, byte[] associatedData)
        {
            FillNonce(state.Nonce, state.Counter, isFinal);
            gcm.Decrypt(
                state.Nonce,
                state.Cipher.AsSpan(0, length),
                state.Tag,
                state.Plain.AsSpan(0, length),
                AssociatedDataForChunk(state.Counter, associatedData));
        }

        private static ReadOnlySpan<byte> AssociatedDataForChunk(uint counter, byte[] associatedData)
        {
            return counter == 0 && associatedData != null ? associatedData : ReadOnlySpan<byte>.Empty;
        }

        private static void FillNonce(byte[] nonce, uint counter, bool isFinal)
        {
            BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(NoncePrefixSize, sizeof(uint)), counter);
            nonce[NonceSize - 1] = isFinal ? (byte)1 : (byte)0;
        }

        private static uint IncrementCounter(uint counter)
        {
            if (counter == uint.MaxValue)
            {
                throw new CryptographicException("Stream is too large to be processed (chunk counter exhausted)");
            }
            return counter + 1;
        }

        private static int FillChunk(Stream stream, byte[] buffer)
        {
            int total = 0;
            while (total < buffer.Length)
            {
                int read = stream.Read(buffer, total, buffer.Length - total);
                if (read == 0)
                {
                    break;
                }
                total += read;
            }
            return total;
        }

        private static async Task<int> FillChunkAsync(Stream stream, byte[] buffer)
        {
            int total = 0;
            while (total < buffer.Length)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(total)).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                total += read;
            }
            return total;
        }

        private sealed class EncryptionState
        {
            public byte[] Nonce;
            public byte[] Header;
            public byte[] Current;
            public byte[] Next;
            public byte[] Cipher;
            public byte[] Tag;
            public int CurrentLength;
            public uint Counter;

            public static EncryptionState Create()
            {
                // The nonce prefix is left all-zero: per-stream uniqueness comes from
                // the derived subkey, so a deterministic nonce is safe.
                return new EncryptionState
                {
                    Nonce = new byte[NonceSize],
                    Header = new byte[sizeof(uint)],
                    Current = new byte[ChunkSize],
                    Next = new byte[ChunkSize],
                    Cipher = new byte[ChunkSize],
                    Tag = new byte[TagSize],
                };
            }

            public void MoveNext(int nextLength)
            {
                (Current, Next) = (Next, Current);
                CurrentLength = nextLength;
                Counter = IncrementCounter(Counter);
            }
        }

        private sealed class DecryptionState
        {
            public byte[] Nonce;
            public byte[] Header;
            public byte[] Cipher;
            public byte[] Plain;
            public byte[] Tag;
            public uint Counter;

            public static DecryptionState Create()
            {
                return new DecryptionState
                {
                    Nonce = new byte[NonceSize],
                    Header = new byte[sizeof(uint)],
                    Cipher = new byte[ChunkSize],
                    Plain = new byte[ChunkSize],
                    Tag = new byte[TagSize],
                };
            }
        }

        public override bool Equals(object obj)
        {
            return obj is AesGcmEncryptionKey otherKey
                && CryptographicOperations.FixedTimeEquals(otherKey._key, _key);
        }

        public override int GetHashCode()
        {
            // Stable and consistent with Equals without exposing the key: only the
            // first four bytes of a one-way hash of the key material are used.
            return BinaryPrimitives.ReadInt32LittleEndian(SHA256.HashData(_key));
        }

        protected override void OnDispose(bool disposing)
        {
            CryptographicOperations.ZeroMemory(_key);
        }
    }
}
