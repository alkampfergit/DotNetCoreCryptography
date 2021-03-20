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
        [Fact]
        public async Task CanEncryptAndDecryptStream()
        {
            const string content = "this test will be encrypted";
            byte[] stringContent = Encoding.UTF8.GetBytes(content);
            using var sourceStream = new MemoryStream(stringContent);
            using var encryptedStream = new MemoryStream();
            using var aes = Aes.Create();
            await Encryptor.EncryptAsync(sourceStream, encryptedStream, aes).ConfigureAwait(false);

            //Now decrypt
            var decryptedMemoryStream = new MemoryStream();
            var readingEncryptedStream = new MemoryStream(encryptedStream.ToArray());
            await Encryptor.DecryptAsync(readingEncryptedStream, decryptedMemoryStream, aes).ConfigureAwait(false);

            var decryptedString = Encoding.UTF8.GetString(decryptedMemoryStream.ToArray());
            Assert.Equal(decryptedString, content);
        }

        [Fact]
        public async Task CanEncryptAndDecryptStreamWithGenericKey()
        {
            const string content = "this test will be encrypted";
            byte[] stringContent = Encoding.UTF8.GetBytes(content);
            using var sourceStream = new MemoryStream(stringContent);
            using var encryptedStream = new MemoryStream();
            using var key = new EncryptionKey();
            await Encryptor.EncryptAsync(sourceStream, encryptedStream, key).ConfigureAwait(false);

            //Now decrypt
            var decryptedMemoryStream = new MemoryStream();
            var readingEncryptedStream = new MemoryStream(encryptedStream.ToArray());
            await Encryptor.DecryptAsync(readingEncryptedStream, decryptedMemoryStream, key).ConfigureAwait(false);

            var decryptedString = Encoding.UTF8.GetString(decryptedMemoryStream.ToArray());
            Assert.Equal(decryptedString, content);
        }
    }
}
