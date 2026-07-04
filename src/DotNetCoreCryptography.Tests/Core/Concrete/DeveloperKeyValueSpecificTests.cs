using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core.Concrete
{
    public abstract class DeveloperKeyValueSpecificTests
    {
        [Fact]
        public async Task Is_able_to_create_folder_if_needed()
        {
            using var key = new AesEncryptionKey();
            var sut = new DeveloperKeyEncryptor(Path.GetTempPath() + Guid.NewGuid().ToString(), allowUnencryptedKeyStore: true);
            var encrypted = await sut.EncryptAsync(key);
            var decrypted = await sut.DecryptAsync(encrypted);
            Assert.Equal(key, decrypted);
        }

        [Fact]
        public async Task Can_resuse_key_upon_dispose()
        {
            // create a key encrypt
            byte[] encrypted;
            using var key = new AesEncryptionKey();

            //own folder so parallel test runs don't race on a shared key file; both
            //instances below point at it to verify the key is reused across instances.
            var keyFolder = Path.GetTempPath() + Guid.NewGuid().ToString();

            var sut = new DeveloperKeyEncryptor(keyFolder, allowUnencryptedKeyStore: true);
            encrypted = await sut.EncryptAsync(key);

            // then decrypt with another instance of the keyvalue store.
            var anotherSut = new DeveloperKeyEncryptor(keyFolder, allowUnencryptedKeyStore: true);
            var decrypted = await anotherSut.DecryptAsync(encrypted);
            Assert.Equal(key, decrypted);
        }
    }
}
