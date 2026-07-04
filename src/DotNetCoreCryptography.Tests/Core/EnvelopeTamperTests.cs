using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    /// <summary>
    /// Verifies the core guarantee of the v2 format (security finding SEC-1): any
    /// modification of an encrypted stream — header, wrapped key, nonce, ciphertext
    /// or tag — makes decryption fail with <see cref="CryptographicException"/>.
    /// </summary>
    public class EnvelopeTamperTests
    {
        private const string Content = "this content will be encrypted and then tampered with";
        private const string Password = "An interesting password";

        private static SecureEncryptor CreateSut()
        {
            return new SecureEncryptor(
                new DeveloperKeyEncryptor(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()), allowUnencryptedKeyStore: true));
        }

        private static async Task<byte[]> EncryptEnvelope(SecureEncryptor sut)
        {
            using var source = new MemoryStream(Encoding.UTF8.GetBytes(Content));
            using var destination = new MemoryStream();
            await sut.Encrypt(source, destination);
            return destination.ToArray();
        }

        private static async Task AssertEnvelopeDecryptionFails(SecureEncryptor sut, byte[] tampered)
        {
            using var source = new MemoryStream(tampered);
            using var destination = new MemoryStream();
            await Assert.ThrowsAsync<CryptographicException>(() => sut.Decrypt(source, destination));
        }

        [Fact]
        public async Task Flipping_any_bit_of_the_envelope_fails_decryption()
        {
            var sut = CreateSut();
            var envelope = await EncryptEnvelope(sut);

            for (int byteIndex = 0; byteIndex < envelope.Length; byteIndex++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    var tampered = (byte[])envelope.Clone();
                    tampered[byteIndex] ^= (byte)(1 << bit);
                    await AssertEnvelopeDecryptionFails(sut, tampered);
                }
            }
        }

        [Fact]
        public async Task Truncating_the_envelope_at_any_length_fails_decryption()
        {
            var sut = CreateSut();
            var envelope = await EncryptEnvelope(sut);

            for (int length = 0; length < envelope.Length; length++)
            {
                await AssertEnvelopeDecryptionFails(sut, envelope[..length]);
            }
        }

        [Theory]
        [InlineData(false, int.MaxValue)]
        [InlineData(false, int.MinValue)]
        [InlineData(false, 0)]
        [InlineData(true, int.MaxValue)]
        [InlineData(true, int.MinValue)]
        [InlineData(true, 0)]
        public async Task SecureEncryptor_rejects_invalid_wrapped_key_lengths_before_allocating(bool v2, int length)
        {
            var sut = CreateSut();
            using var source = new MemoryStream(BuildEnvelopeWithWrappedKeyLength(v2, length));
            using var destination = new MemoryStream();

            await Assert.ThrowsAsync<CryptographicException>(() => sut.Decrypt(source, destination));
        }

        [Theory]
        [InlineData(false, int.MaxValue)]
        [InlineData(false, int.MinValue)]
        [InlineData(false, 0)]
        [InlineData(true, int.MaxValue)]
        [InlineData(true, int.MinValue)]
        [InlineData(true, 0)]
        public async Task AsymmetricSecureEncryptor_rejects_invalid_wrapped_key_lengths_before_allocating(bool v2, int length)
        {
            using var key = new RsaEncryptionKey();
            using var source = new MemoryStream(BuildEnvelopeWithWrappedKeyLength(v2, length));
            using var destination = new MemoryStream();

            await Assert.ThrowsAsync<CryptographicException>(
                () => AsymmetricSecureEncryptor.Decrypt(key, source, destination));
        }

        [Fact]
        public async Task Swapping_the_wrapped_key_between_envelopes_fails_decryption()
        {
            var sut = CreateSut();
            var first = await EncryptEnvelope(sut);
            var second = await EncryptEnvelope(sut);

            //graft the (valid) wrapped key of the second envelope onto the first:
            //the header is bound to the payload as associated data, so decryption
            //must fail even though every part is individually well-formed.
            var wrappedKeyLength = BitConverter.ToInt32(first, 4);
            Assert.Equal(wrappedKeyLength, BitConverter.ToInt32(second, 4));
            var tampered = (byte[])first.Clone();
            Array.Copy(second, 8, tampered, 8, wrappedKeyLength);

            await AssertEnvelopeDecryptionFails(sut, tampered);
        }

        [Fact]
        public async Task Flipping_one_bit_per_byte_of_the_asymmetric_envelope_fails_decryption()
        {
            using var key = new RsaEncryptionKey();
            using var publicKey = AsymmetricEncryptionKey.CreateFromSerializedVersion(key.SerializePublicKey());
            using var source = new MemoryStream(Encoding.UTF8.GetBytes(Content));
            using var destination = new MemoryStream();
            await AsymmetricSecureEncryptor.Encrypt(publicKey, source, destination);
            var envelope = destination.ToArray();

            //one bit per byte keeps the number of RSA private-key operations sane
            for (int byteIndex = 0; byteIndex < envelope.Length; byteIndex++)
            {
                var tampered = (byte[])envelope.Clone();
                tampered[byteIndex] ^= (byte)(1 << (byteIndex % 8));
                using var tamperedSource = new MemoryStream(tampered);
                using var tamperedDestination = new MemoryStream();
                await Assert.ThrowsAsync<CryptographicException>(
                    () => AsymmetricSecureEncryptor.Decrypt(key, tamperedSource, tamperedDestination));
            }
        }

        [Fact]
        public void Tampering_password_encrypted_data_never_yields_the_original_plaintext()
        {
            var content = Encoding.UTF8.GetBytes(Content);
            var encrypted = StaticEncryptor.AesEncryptWithPassword(content, Password);

            //flipping magic bytes reroutes the stream to the cheap legacy (v1) path,
            //so every bit can be exercised without paying the modern KDF cost
            for (int byteIndex = 0; byteIndex < 4; byteIndex++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    AssertTamperNeverYieldsPlaintext(encrypted, content, byteIndex, bit);
                }
            }

            //each tampered decrypt on the v2 path costs a full PBKDF2 run (600k
            //iterations), so sample one byte per structural region instead of
            //flipping every byte; exhaustive per-bit coverage of the AEAD layer
            //itself lives in AesGcmEncryptionKeyTests. Regions: salt start/end,
            //nonce prefix, chunk header, first ciphertext byte, last tag byte.
            int[] sampledIndexes = { 4, 19, 20, 27, 31, encrypted.Length - 1 };
            foreach (var byteIndex in sampledIndexes)
            {
                AssertTamperNeverYieldsPlaintext(encrypted, content, byteIndex, bit: 0);
            }
        }

        private static void AssertTamperNeverYieldsPlaintext(byte[] encrypted, byte[] content, int byteIndex, int bit)
        {
            var tampered = (byte[])encrypted.Clone();
            tampered[byteIndex] ^= (byte)(1 << bit);
            try
            {
                //flipping a byte of the magic reroutes the stream to the legacy
                //(v1, unauthenticated) decryption path, which uses a different KDF
                //and therefore can only ever produce garbage; everywhere else the
                //authenticated v2 path must throw.
                var decrypted = StaticEncryptor.AesDecryptWithPassword(tampered, Password);
                Assert.NotEqual(content, decrypted);
            }
            catch (CryptographicException)
            {
                //expected: tamper detected
            }
        }

        private static byte[] BuildEnvelopeWithWrappedKeyLength(bool v2, int length)
        {
            if (!v2)
            {
                return BitConverter.GetBytes(length);
            }

            var envelope = new byte[8];
            envelope[0] = 0x44;
            envelope[1] = 0x4E;
            envelope[2] = 0x43;
            envelope[3] = 0x02;
            BitConverter.GetBytes(length).CopyTo(envelope, 4);
            return envelope;
        }

        [Fact]
        public void Password_encrypted_data_roundtrips()
        {
            var content = Encoding.UTF8.GetBytes(Content);
            var encrypted = StaticEncryptor.AesEncryptWithPassword(content, Password);
            Assert.Equal(content, StaticEncryptor.AesDecryptWithPassword(encrypted, Password));
        }

        [Fact]
        public async Task Decrypting_with_the_wrong_password_fails()
        {
            var content = Encoding.UTF8.GetBytes(Content);
            var encrypted = await StaticEncryptor.AesEncryptWithPasswordAsync(content, Password);
            await Assert.ThrowsAsync<CryptographicException>(
                () => StaticEncryptor.AesDecryptWithPasswordAsync(encrypted, "wrong password"));
        }
    }
}
