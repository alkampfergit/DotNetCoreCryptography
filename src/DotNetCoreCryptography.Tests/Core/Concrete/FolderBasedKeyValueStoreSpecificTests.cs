using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core.Concrete
{
    public class FolderBasedKeyValueStoreSpecificTests
    {
        [Fact]
        public async Task Unable_to_decrypt_if_wrong_password()
        {
            using var key = new EncryptionKey();
            string keyMaterialFolder = Path.GetTempPath() + Guid.NewGuid().ToString();
            var sut = new FolderBasedKeyValueStore(
                keyMaterialFolder,
                "password");
            var encrypted = await sut.EncryptAsync(key).ConfigureAwait(false);

            //We should not be able to create a sut where already exists a key
            //with an invalid password
            Assert.Throws<AggregateException>(() => new FolderBasedKeyValueStore(
               keyMaterialFolder,
               "another-password"));
        }
    }
}
