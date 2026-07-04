using DotNetCoreCryptography.Azure;
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
        // Shared body for the round-trip test. Each concrete store declares its own
        // test method (with the attribute it needs - [Fact] or [SkippableFact]) so
        // the Azure store can be skipped independently without an inherited-[Fact]
        // clash on an overridden method.
        protected async Task AssertEncryptDecryptRoundTrip()
        {
            using var key = new AesEncryptionKey();
            var sut = CreateSut();
            var encrypted = await sut.EncryptAsync(key);
            var decrypted = await sut.DecryptAsync(encrypted);
            Assert.Equal(key, decrypted);
        }

        protected abstract IKeyEncryptor CreateSut();
    }

    public class DevelopKeyValueStoreTests : GenericKeyValueStoreTests
    {
        [Fact]
        public Task Is_able_to_encrypt_and_decrypt_a_key() => AssertEncryptDecryptRoundTrip();

        protected override IKeyEncryptor CreateSut()
        {
            //each test gets its own folder so parallel test runs don't race on a shared key file.
            return new DeveloperKeyEncryptor(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()), allowUnencryptedKeyStore: true);
        }
    }

    public class AzureKeyValueStoreTests : GenericKeyValueStoreTests
    {
        // Live integration test: it talks to a real Azure Key Vault via
        // DefaultAzureCredential. When Azure credentials are not configured (e.g.
        // pull_request CI runs, which do not receive the AZURE_* secrets, or a local
        // dev machine) the test is reported as SKIPPED with a reason - not passed and
        // not failed - so it is visible in the test report without turning CI red for
        // a reason unrelated to the code. It runs for real wherever the credentials
        // are present (push / mainline builds).
        [SkippableFact]
        public async Task Is_able_to_encrypt_and_decrypt_a_key()
        {
            Skip.IfNot(
                AzureCredentialsAvailable(),
                "Azure credentials (AZURE_CLIENT_ID/AZURE_TENANT_ID/AZURE_CLIENT_SECRET) are not " +
                "configured; skipping the live Azure Key Vault integration test.");

            await AssertEncryptDecryptRoundTrip();
        }

        private static bool AzureCredentialsAvailable()
        {
            return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"))
                && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AZURE_TENANT_ID"))
                && !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET"));
        }

        protected override IKeyEncryptor CreateSut()
        {
            return new AzureKeyVaultStoreKeyEncryptor("https://test-kv-alk.vault.azure.net/", "test");
        }
    }

    public class FolderBasedAesKeyValueStoreTests : GenericKeyValueStoreTests
    {
        [Fact]
        public Task Is_able_to_encrypt_and_decrypt_a_key() => AssertEncryptDecryptRoundTrip();

        protected override IKeyEncryptor CreateSut()
        {
            return new FolderBasedKeyEncryptor(Path.GetTempPath()+ Guid.NewGuid().ToString(), "test");
        }
    }
}
