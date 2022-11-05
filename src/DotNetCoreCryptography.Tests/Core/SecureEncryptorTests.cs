using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
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
            Assert.Equal(decryptedContent, someContenttoBeEncrypted);
        }

        const string someContenttoBeEncrypted = "this test will be encrypted";

        private Stream GenerateStreamToEncrypt()
        {
            byte[] stringContent = Encoding.UTF8.GetBytes(someContenttoBeEncrypted);
            return new MemoryStream(stringContent);
        }

        private SecureEncryptor CreateSut()
        {
            //we could use a mock, but it is simpler for now using a know working store.
            return new SecureEncryptor(new DeveloperKeyEncryptor(Path.GetTempPath()));
        }
    }
}
