using DotNetCoreCryptographyCore;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class EncryptorTests
    {
        private const string Password = "An interesting password";

        [Fact]
        public async Task Can_Encrypt_And_Decrypt_Stream_with_password()
        {
            const string content = "this test will be encrypted";
            byte[] stringContent = Encoding.UTF8.GetBytes(content);
            using var sourceStream = new MemoryStream(stringContent);
            using var encryptedStream = new MemoryStream();
            await StaticEncryptor.AesEncryptWithPasswordAsync(
                sourceStream,
                encryptedStream,
                Password).ConfigureAwait(false);

            //Now decrypt
            var decryptedMemoryStream = new MemoryStream();
            var readingEncryptedStream = new MemoryStream(encryptedStream.ToArray());
            await StaticEncryptor.AesDecryptWithPasswordAsync(
                readingEncryptedStream,
                decryptedMemoryStream,
                Password).ConfigureAwait(false);

            var decryptedString = Encoding.UTF8.GetString(decryptedMemoryStream.ToArray());
            Assert.Equal(decryptedString, content);
        }

        [Fact]
        public async Task Can_Encrypt_And_Decrypt_bytes_with_password()
        {
            const string content = "this test will be encrypted";
            byte[] stringContent = Encoding.UTF8.GetBytes(content);

            var encrypted = await StaticEncryptor.AesEncryptWithPasswordAsync(
                stringContent,
                Password).ConfigureAwait(false);

            //Now decrypt
            var decrypted = await StaticEncryptor.AesDecryptWithPasswordAsync(
                encrypted,
                Password).ConfigureAwait(false);

            Assert.Equal(stringContent, decrypted);
        }

        public void Can_Encrypt_And_Decrypt_bytes_with_password_non_Async()
        {
            const string content = "this test will be encrypted";
            byte[] stringContent = Encoding.UTF8.GetBytes(content);

            var encrypted = StaticEncryptor.AesEncryptWithPassword(
                stringContent,
                Password);

            //Now decrypt
            var decrypted = StaticEncryptor.AesDecryptWithPassword(
                encrypted,
                Password);

            Assert.Equal(stringContent, decrypted);
        }

        [Fact]
        public async Task CanEncryptAndDecryptStreamWithGenericKey()
        {
            const string content = "this test will be encrypted";
            byte[] stringContent = Encoding.UTF8.GetBytes(content);
            using var sourceStream = new MemoryStream(stringContent);
            using var encryptedStream = new MemoryStream();
            using var key = new AesEncryptionKey();
            await StaticEncryptor.EncryptAsync(sourceStream, encryptedStream, key).ConfigureAwait(false);

            //Now decrypt
            var decryptedMemoryStream = new MemoryStream();
            var readingEncryptedStream = new MemoryStream(encryptedStream.ToArray());
            await StaticEncryptor.DecryptAsync(readingEncryptedStream, decryptedMemoryStream, key).ConfigureAwait(false);

            var decryptedString = Encoding.UTF8.GetString(decryptedMemoryStream.ToArray());
            Assert.Equal(decryptedString, content);
        }
    }
}
