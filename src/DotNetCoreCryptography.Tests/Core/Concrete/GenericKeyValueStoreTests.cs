using DotNetCoreCryptography.Azure;
using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core.Concrete
{
    public abstract class GenericKeyValueStoreTests : IDisposable
    {
        protected GenericKeyValueStoreTests()
        {
            //AZURE_TENANT_ID =#Tenant where the application is installed
            //AZURE_CLIENT_SECRET =#Client secret for oauth enterprise azure app
            //AZURE_CLIENT_ID =#Client id for oauth enterprise azure app
            Environment.SetEnvironmentVariable("AZURE_TENANT_ID", "");    
            Environment.SetEnvironmentVariable("AZURE_CLIENT_ID", "");    
            Environment.SetEnvironmentVariable("AZURE_CLIENT_SECRET", "");    
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable("AZURE_TENANT_ID", null);
            Environment.SetEnvironmentVariable("AZURE_CLIENT_ID", null);
            Environment.SetEnvironmentVariable("AZURE_CLIENT_SECRET", null);
        }

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

    public class DevelopKeyValueStoreTests : GenericKeyValueStoreTests
    {
        protected override IKeyEncryptor CreateSut()
        {
            return new DeveloperKeyEncryptor(Path.GetTempPath());
        }
    }

    public class AzureKeyValueStoreTests : GenericKeyValueStoreTests
    {
        protected override IKeyEncryptor CreateSut()
        {
            return new AzureKeyVaultStoreKeyEncryptor("https://test-kv-alk.vault.azure.net/", "test");
        }
    }

    public class FolderBasedAesKeyValueStoreTests : GenericKeyValueStoreTests
    {
        protected override IKeyEncryptor CreateSut()
        {
            return new FolderBasedKeyEncryptor(Path.GetTempPath()+ Guid.NewGuid().ToString(), "test");
        }
    }
}
