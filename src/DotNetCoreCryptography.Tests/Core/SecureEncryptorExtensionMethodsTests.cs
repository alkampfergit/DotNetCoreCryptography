using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class SecureEncryptorExtensionMethodsTests
    {
        [Fact]
        public async Task Can_encrypt_plain_string()
        {
            var sut = CreateSut();
            const string stringToEncrypt = "This string is to be encrypted";
            string encrypted = await sut.EncryptAsync(stringToEncrypt);

            Assert.NotEqual(stringToEncrypt, encrypted);
            var decrypted = await sut.DecryptAsync(encrypted);
            Assert.Equal(stringToEncrypt, decrypted);
        }

        private static SecureEncryptor CreateSut()
        {
            //we could use a mock, but it is simpler for now using a know working store.
            //each test gets its own folder so parallel test runs don't race on a shared key file.
            return new SecureEncryptor(new DeveloperKeyEncryptor(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()), allowUnencryptedKeyStore: true));
        }
    }
}
