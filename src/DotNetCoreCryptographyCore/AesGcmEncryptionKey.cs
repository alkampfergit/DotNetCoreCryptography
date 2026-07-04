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
    /// <para>Stream format (STREAM-style chunked AEAD):</para>
    /// <code>
    /// [ 7-byte random nonce prefix ]
    /// [ chunk 0 ][ chunk 1 ] ... [ final chunk ]
    ///
    /// chunk   := [ 4-byte big-endian header ][ ciphertext ][ 16-byte tag ]
    /// header  := plaintext length (64 KiB except final chunk) | 0x80000000 on final chunk
    /// nonce_i := prefix || 32-bit big-endian chunk counter || final-flag byte
    /// </code>
    /// <para>
    /// The per-chunk counter defeats chunk reordering, the final flag defeats
    /// truncation, and the optional associated data is authenticated together with
    /// the first chunk. Note that decryption writes each chunk to the destination
    /// as soon as that chunk is authenticated; if a later chunk fails, the
    /// destination contains an authenticated prefix of the plaintext and the
    /// operation throws.
    /// </para>
    /// </remarks>
    public sealed class AesGcmEncryptionKey : EncryptionKey
    {
        private const int KeySizeInBytes = 32;
        private const int ChunkSize = 64 * 1024;
        private const int NoncePrefixSize = 7;
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const uint FinalChunkFlag = 0x8000_0000u;

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
            using var gcm = new AesGcm(_key, TagSize);
            var state = EncryptionState.Create();
            destinationStream.Write(state.Nonce, 0, NoncePrefixSize);

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

        public override async Task EncryptAsync(Stream sourceStream, Stream destinationStream, byte[] associatedData = null)
        {
            using var gcm = new AesGcm(_key, TagSize);
            var state = EncryptionState.Create();
            await destinationStream.WriteAsync(state.Nonce.AsMemory(0, NoncePrefixSize)).ConfigureAwait(false);

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

        public override void Decrypt(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null)
        {
            try
            {
                using var gcm = new AesGcm(_key, TagSize);
                var state = DecryptionState.Create();
                encryptedStream.ReadExactly(state.Nonce.AsSpan(0, NoncePrefixSize));

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
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }

        public override async Task DecryptAsync(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null)
        {
            try
            {
                using var gcm = new AesGcm(_key, TagSize);
                var state = DecryptionState.Create();
                await encryptedStream.ReadExactlyAsync(state.Nonce.AsMemory(0, NoncePrefixSize)).ConfigureAwait(false);

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
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
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
                var state = new EncryptionState
                {
                    Nonce = new byte[NonceSize],
                    Header = new byte[sizeof(uint)],
                    Current = new byte[ChunkSize],
                    Next = new byte[ChunkSize],
                    Cipher = new byte[ChunkSize],
                    Tag = new byte[TagSize],
                };
                RandomNumberGenerator.Fill(state.Nonce.AsSpan(0, NoncePrefixSize));
                return state;
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
