using DotNetCoreCryptographyCore;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class AesGcmEncryptionKeyTests
    {
        private const int ChunkSize = 64 * 1024;
        private const int NoncePrefixSize = 7;
        private const int ChunkHeaderSize = 4;
        private const int TagSize = 16;

        // Current stream layout: 4-byte magic + 32-byte salt before the first chunk.
        private static readonly byte[] GcmStreamMagic = { 0x44, 0x4E, 0x43, 0x10 };
        private const int SaltSize = 32;
        private const int StreamHeaderSize = 4 + SaltSize;

        private static byte[] GenerateContent(int length)
        {
            var content = new byte[length];
            //deterministic content so failures are reproducible
            new Random(length).NextBytes(content);
            return content;
        }

        private static byte[] Encrypt(AesGcmEncryptionKey key, byte[] content, byte[] associatedData = null)
        {
            using var source = new MemoryStream(content);
            using var destination = new MemoryStream();
            key.Encrypt(source, destination, associatedData);
            return destination.ToArray();
        }

        private static byte[] Decrypt(AesGcmEncryptionKey key, byte[] encrypted, byte[] associatedData = null)
        {
            using var source = new MemoryStream(encrypted);
            using var destination = new MemoryStream();
            key.Decrypt(source, destination, associatedData);
            return destination.ToArray();
        }

        [Fact]
        public void Default_key_is_aes_gcm()
        {
            using var key = EncryptionKey.CreateDefault();
            Assert.IsType<AesGcmEncryptionKey>(key);
        }

        [Fact]
        public void Serialization_roundtrip_and_byte_mark()
        {
            using var key = new AesGcmEncryptionKey();
            var serialized = key.Serialize();
            Assert.Equal(33, serialized.Length);
            Assert.Equal((byte)KeyType.Aes256Gcm, serialized[0]);

            using var deserialized = EncryptionKey.CreateFromSerializedVersion(serialized);
            Assert.Equal(key, deserialized);
        }

        [Fact]
        public void Deserialization_rejects_invalid_length()
        {
            var serialized = new byte[20];
            serialized[0] = (byte)KeyType.Aes256Gcm;
            Assert.Throws<CryptographicException>(() => new AesGcmEncryptionKey(serialized));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(ChunkSize - 1)]
        [InlineData(ChunkSize)]
        [InlineData(ChunkSize + 1)]
        [InlineData((3 * ChunkSize) + 17)]
        public void Roundtrip_at_chunk_boundaries(int length)
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(length);
            var encrypted = Encrypt(key, content);
            Assert.Equal(content, Decrypt(key, encrypted));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(ChunkSize)]
        [InlineData((2 * ChunkSize) + 100)]
        public async Task Roundtrip_at_chunk_boundaries_async(int length)
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(length);
            using var source = new MemoryStream(content);
            using var encryptedMs = new MemoryStream();
            await key.EncryptAsync(source, encryptedMs);

            using var encryptedSource = new MemoryStream(encryptedMs.ToArray());
            using var decryptedMs = new MemoryStream();
            await key.DecryptAsync(encryptedSource, decryptedMs);
            Assert.Equal(content, decryptedMs.ToArray());
        }

        [Fact]
        public async Task Sync_and_async_formats_are_interchangeable()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(ChunkSize + 100);
            var encrypted = Encrypt(key, content);

            using var source = new MemoryStream(encrypted);
            using var destination = new MemoryStream();
            await key.DecryptAsync(source, destination);
            Assert.Equal(content, destination.ToArray());
        }

        [Fact]
        public void Encrypting_same_content_twice_yields_different_ciphertext()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(100);
            Assert.NotEqual(Encrypt(key, content), Encrypt(key, content));
        }

        [Fact]
        public void Flipping_any_bit_of_the_ciphertext_fails_decryption()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(100);
            var encrypted = Encrypt(key, content);

            for (int byteIndex = 0; byteIndex < encrypted.Length; byteIndex++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    var tampered = (byte[])encrypted.Clone();
                    tampered[byteIndex] ^= (byte)(1 << bit);
                    Assert.Throws<CryptographicException>(() => Decrypt(key, tampered));
                }
            }
        }

        [Fact]
        public void Truncation_at_any_length_fails_decryption()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(100);
            var encrypted = Encrypt(key, content);

            for (int length = 0; length < encrypted.Length; length++)
            {
                var truncated = encrypted[..length];
                Assert.Throws<CryptographicException>(() => Decrypt(key, truncated));
            }
        }

        [Fact]
        public void Removing_the_final_chunk_fails_decryption()
        {
            using var key = new AesGcmEncryptionKey();
            const int finalChunkPlaintext = 100;
            var content = GenerateContent((2 * ChunkSize) + finalChunkPlaintext);
            var encrypted = Encrypt(key, content);

            //drop the whole final chunk so the stream ends after a valid, complete
            //non-final chunk: decryption must notice the missing final marker.
            var truncated = encrypted[..^(ChunkHeaderSize + finalChunkPlaintext + TagSize)];
            Assert.Throws<CryptographicException>(() => Decrypt(key, truncated));
        }

        [Fact]
        public void Swapping_two_chunks_fails_decryption()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent((2 * ChunkSize) + 100);
            var encrypted = Encrypt(key, content);

            const int chunkTotalSize = ChunkHeaderSize + ChunkSize + TagSize;
            var tampered = (byte[])encrypted.Clone();
            var firstChunk = encrypted.AsSpan(StreamHeaderSize, chunkTotalSize).ToArray();
            var secondChunk = encrypted.AsSpan(StreamHeaderSize + chunkTotalSize, chunkTotalSize).ToArray();
            secondChunk.CopyTo(tampered, StreamHeaderSize);
            firstChunk.CopyTo(tampered, StreamHeaderSize + chunkTotalSize);

            Assert.Throws<CryptographicException>(() => Decrypt(key, tampered));
        }

        [Fact]
        public void Trailing_data_after_final_chunk_fails_decryption()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(100);
            var encrypted = Encrypt(key, content);

            var withTrailing = new byte[encrypted.Length + 1];
            encrypted.CopyTo(withTrailing, 0);
            Assert.Throws<CryptographicException>(() => Decrypt(key, withTrailing));
        }

        [Fact]
        public void Associated_data_is_bound_to_the_ciphertext()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(100);
            var associatedData = new byte[] { 1, 2, 3, 4 };
            var encrypted = Encrypt(key, content, associatedData);

            Assert.Equal(content, Decrypt(key, encrypted, associatedData));
            Assert.Throws<CryptographicException>(() => Decrypt(key, encrypted));
            Assert.Throws<CryptographicException>(() => Decrypt(key, encrypted, new byte[] { 1, 2, 3, 5 }));
        }

        [Fact]
        public void Decrypting_with_another_key_fails()
        {
            using var key = new AesGcmEncryptionKey();
            using var otherKey = new AesGcmEncryptionKey();
            var encrypted = Encrypt(key, GenerateContent(100));
            Assert.Throws<CryptographicException>(() => Decrypt(otherKey, encrypted));
        }

        [Fact]
        public void Works_through_static_encryptor()
        {
            const string content = "this test will be encrypted";
            using var key = EncryptionKey.CreateDefault();
            var encrypted = StaticEncryptor.Encrypt(content, key);
            Assert.Equal(content, StaticEncryptor.Decrypt(encrypted, key));
        }

        [Fact]
        public void New_stream_starts_with_magic_and_salt()
        {
            using var key = new AesGcmEncryptionKey();
            var encrypted = Encrypt(key, GenerateContent(100));

            Assert.True(encrypted.Length >= StreamHeaderSize);
            Assert.Equal(GcmStreamMagic, encrypted[..GcmStreamMagic.Length]);
        }

        [Fact]
        public void Each_encryption_uses_a_fresh_salt()
        {
            using var key = new AesGcmEncryptionKey();
            var content = GenerateContent(100);
            var first = Encrypt(key, content);
            var second = Encrypt(key, content);

            //the 32-byte salt that follows the magic must differ between two calls,
            //otherwise the derived subkeys (and nonces) would repeat.
            var firstSalt = first.AsSpan(GcmStreamMagic.Length, SaltSize).ToArray();
            var secondSalt = second.AsSpan(GcmStreamMagic.Length, SaltSize).ToArray();
            Assert.NotEqual(firstSalt, secondSalt);
        }

        [Fact]
        public void Legacy_prefix_format_is_still_decryptable()
        {
            //Reproduces the pre-hardening wire format (7-byte random nonce prefix,
            //no magic, chunks encrypted directly with the long-term key) and proves
            //the current Decrypt still reads it. Guards against a regression that
            //would make previously-encrypted data unreadable.
            using var key = new AesGcmEncryptionKey();
            var rawKey = key.Serialize().AsSpan(1).ToArray(); // drop the KeyType byte
            var plaintext = GenerateContent(200);

            var legacy = BuildLegacySingleChunkStream(rawKey, plaintext);
            Assert.Equal(plaintext, Decrypt(key, legacy));
        }

        [Fact]
        public async Task Legacy_prefix_format_is_still_decryptable_async()
        {
            using var key = new AesGcmEncryptionKey();
            var rawKey = key.Serialize().AsSpan(1).ToArray();
            var plaintext = GenerateContent(200);

            var legacy = BuildLegacySingleChunkStream(rawKey, plaintext);
            using var source = new MemoryStream(legacy);
            using var destination = new MemoryStream();
            await key.DecryptAsync(source, destination);
            Assert.Equal(plaintext, destination.ToArray());
        }

        /// <summary>
        /// Builds a single-chunk stream in the legacy format:
        /// <c>[7-byte random prefix][4-byte header][ciphertext][16-byte tag]</c> with
        /// nonce = prefix || 0u || 1 (final) and no associated data.
        /// </summary>
        private static byte[] BuildLegacySingleChunkStream(byte[] rawKey, byte[] plaintext)
        {
            var prefix = RandomNumberGenerator.GetBytes(NoncePrefixSize);
            var nonce = new byte[12];
            prefix.CopyTo(nonce, 0);
            // counter 0 (bytes 7..10 stay zero) and final-flag byte at index 11
            nonce[11] = 1;

            var header = new byte[ChunkHeaderSize];
            uint headerValue = (uint)plaintext.Length | 0x8000_0000u;
            header[0] = (byte)(headerValue >> 24);
            header[1] = (byte)(headerValue >> 16);
            header[2] = (byte)(headerValue >> 8);
            header[3] = (byte)headerValue;

            var cipher = new byte[plaintext.Length];
            var tag = new byte[TagSize];
            using (var gcm = new AesGcm(rawKey, TagSize))
            {
                gcm.Encrypt(nonce, plaintext, cipher, tag);
            }

            using var ms = new MemoryStream();
            ms.Write(prefix);
            ms.Write(header);
            ms.Write(cipher);
            ms.Write(tag);
            return ms.ToArray();
        }
    }
}
