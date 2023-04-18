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
            var sut = new DeveloperKeyEncryptor(Path.GetTempPath() + Guid.NewGuid().ToString());
            var encrypted = await sut.EncryptAsync(key).ConfigureAwait(false);
            var decrypted = await sut.DecryptAsync(encrypted).ConfigureAwait(false);
            Assert.Equal(key, decrypted);
        }

        [Fact]
        public async Task Can_resuse_key_upon_dispose()
        {
            // create a key encrypt 
            byte[] encrypted;
            using var key = new AesEncryptionKey();

            var sut = new DeveloperKeyEncryptor(Path.GetTempPath());
            encrypted = await sut.EncryptAsync(key).ConfigureAwait(false);

            // then decrypt with another instance of the keyvalue store.
            var anotherSut = new DeveloperKeyEncryptor(Path.GetTempPath());
            var decrypted = await anotherSut.DecryptAsync(encrypted).ConfigureAwait(false);
            Assert.Equal(key, decrypted);
        }
    }
}
