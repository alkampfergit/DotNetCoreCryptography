using DotNetCoreCryptography.Azure;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    /// <summary>
    /// Offline tests for the versioned Azure Key Vault wrapped-key blob format
    /// (Finding 2). These exercise the pure build/parse logic without talking to a
    /// live vault; the end-to-end round-trip is covered by the live
    /// <c>AzureKeyValueStoreTests</c> integration test where credentials exist.
    /// </summary>
    public class AzureKeyVaultBlobFormatTests
    {
        private const string VersionedKeyId =
            "https://test-kv-alk.vault.azure.net/keys/test/0123456789abcdef0123456789abcdef";

        [Fact]
        public void Build_and_parse_roundtrip_preserves_key_id_and_ciphertext()
        {
            var ciphertext = new byte[] { 1, 2, 3, 4, 250, 251, 252, 0, 255 };

            var blob = AzureKeyVaultStoreKeyEncryptor.BuildVersionedBlob(VersionedKeyId, ciphertext);
            var parsedKeyId = AzureKeyVaultStoreKeyEncryptor.ParseVersionedBlob(blob, out var parsedCiphertext);

            Assert.Equal(VersionedKeyId, parsedKeyId);
            Assert.Equal(ciphertext, parsedCiphertext);
        }

        [Fact]
        public void Built_blob_starts_with_magic()
        {
            var blob = AzureKeyVaultStoreKeyEncryptor.BuildVersionedBlob(VersionedKeyId, new byte[] { 9 });
            Assert.Equal(new byte[] { 0x44, 0x4E, 0x43, 0x20 }, blob[..4]);
        }

        [Fact]
        public void Parse_rejects_truncated_blob()
        {
            var blob = AzureKeyVaultStoreKeyEncryptor.BuildVersionedBlob(VersionedKeyId, new byte[] { 9, 8, 7 });

            // Drop the ciphertext so the declared key-id length runs past the buffer.
            var truncated = blob[..(blob.Length - 4)];
            Assert.Throws<CryptographicException>(
                () => AzureKeyVaultStoreKeyEncryptor.ParseVersionedBlob(truncated, out _));
        }

        [Fact]
        public void Parse_rejects_blob_with_only_a_header()
        {
            var tooShort = Encoding.ASCII.GetBytes("DNC");
            Assert.Throws<CryptographicException>(
                () => AzureKeyVaultStoreKeyEncryptor.ParseVersionedBlob(tooShort, out _));
        }
    }
}
