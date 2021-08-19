using DotNetCoreCryptography.Azure;
using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core.Concrete
{
    public abstract class GenericKeyEncryptorTests
    {
        [Fact]
        public async Task Is_able_to_encrypt_and_decrypt_a_key()
        {
            using var key = new AesEncryptionKey();
            var sut = CreateSut();
            var encrypted = await sut.EncryptAsync(key).ConfigureAwait(false);
            var decrypted = await sut.DecryptAsync(encrypted).ConfigureAwait(false);
            Assert.Equal(key, decrypted);
        }

        protected abstract IKeyEncryptor CreateSut();
    }

    public class DevelopKeyValueStoreTests : GenericKeyEncryptorTests
    {
        protected override IKeyEncryptor CreateSut()
        {
            return new DevelopKeyEncryptor(Path.GetTempPath());
        }
    }

    public class AzureKeyValueStoreTests : GenericKeyEncryptorTests
    {
        protected override IKeyEncryptor CreateSut()
        {
            return new AzureKeyVaultKeyEncryptor("https://test-kv-alk.vault.azure.net/", "test");
        }
    }

    public class FolderBasedAesKeyValueStoreTests : GenericKeyEncryptorTests
    {
        protected override IKeyEncryptor CreateSut()
        {
            return new FolderBasedKeyEncryptor(Path.GetTempPath()+ Guid.NewGuid().ToString(), "test");
        }
    }
}
