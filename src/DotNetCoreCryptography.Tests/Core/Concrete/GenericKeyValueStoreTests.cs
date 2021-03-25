using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core.Concrete
{
    public abstract class GenericKeyValueStoreTests
    {
        [Fact]
        public async Task Is_able_to_encrypt_and_decrypt_a_key()
        {
            using var key = new AesEncryptionKey();
            var sut = CreateSut();
            var encrypted = await sut.EncryptAsync(key).ConfigureAwait(false);
            var decrypted = await sut.DecriptAsync(encrypted).ConfigureAwait(false);
            Assert.Equal(key, decrypted);
        }

        protected abstract IKeyVaultStore CreateSut();
    }

    public class DevelopKeyValueStoreTests : GenericKeyValueStoreTests
    {
        protected override IKeyVaultStore CreateSut()
        {
            return new DevelopKeyValueStore(Path.GetTempPath());
        }
    }

    public class FolderBasedAesKeyValueStoreTests : GenericKeyValueStoreTests
    {
        protected override IKeyVaultStore CreateSut()
        {
            return new FolderBasedKeyValueStore(Path.GetTempPath()+ Guid.NewGuid().ToString(), "test");
        }
    }
}
