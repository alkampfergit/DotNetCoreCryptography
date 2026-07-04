using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class SecureEncryptorTests
    {
        [Fact]
        public async Task Full_secure_encryption_test()
        {
            var sut = CreateSut();
            using var streamToEncrypt = GenerateStreamToEncrypt();

            //ok now we need to secure encrypt and decrypt the stream
            using var encryptedStream = new MemoryStream();
            await sut.Encrypt(streamToEncrypt, encryptedStream);

            //now we want to read again and decrypt
            var sourceEncryptedStream = new MemoryStream(encryptedStream.ToArray());
            using var decryptedStream = new MemoryStream();
            await sut.Decrypt(sourceEncryptedStream, decryptedStream);

            var decryptedContent = Encoding.UTF8.GetString(decryptedStream.ToArray());
            Assert.Equal(someContenttoBeEncrypted, decryptedContent);
        }

        const string someContenttoBeEncrypted = "this test will be encrypted";

        private static MemoryStream GenerateStreamToEncrypt()
        {
            byte[] stringContent = Encoding.UTF8.GetBytes(someContenttoBeEncrypted);
            return new MemoryStream(stringContent);
        }

        private static SecureEncryptor CreateSut()
        {
            //we could use a mock, but it is simpler for now using a know working store.
            //each test gets its own folder so parallel test runs don't race on a shared key file.
            return new SecureEncryptor(new DeveloperKeyEncryptor(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()), allowUnencryptedKeyStore: true));
        }
    }
}
