using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using DotNetCoreCryptographyCore;
using System;
using System.Threading.Tasks;

namespace DotNetCoreCryptography.Azure
{
    public class AzureKeyVaultStore : IKeyVaultStore
    {
        private readonly string _actualKeyName;
        private KeyClient _keyClient;

        public AzureKeyVaultStore(
            string keyValueStoreAddress,
            string actualKeyName)
        {
            _keyClient = new KeyClient(new Uri(keyValueStoreAddress), new DefaultAzureCredential());
            _actualKeyName = actualKeyName;
        }

        public async Task<EncryptionKey> DecriptAsync(byte[] encryptedKey)
        {
            var key = await _keyClient.GetKeyAsync(_actualKeyName);
            var cryptoClient = new CryptographyClient(keyId: key.Value.Id, credential: new DefaultAzureCredential());

            var result = await cryptoClient.DecryptAsync(
                EncryptionAlgorithm.RsaOaep256,
                encryptedKey,
                default);
            return EncryptionKey.CreateFromSerializedVersion(result.Plaintext);
        }

        public async Task<byte[]> EncryptAsync(EncryptionKey key)
        {
            var keyVaultKey = await _keyClient.GetKeyAsync(_actualKeyName);
            var cryptoClient = new CryptographyClient(keyId: keyVaultKey.Value.Id, credential: new DefaultAzureCredential());

            var result = await cryptoClient.EncryptAsync(
                EncryptionAlgorithm.RsaOaep256,
                key.Serialize(),
                default);
            return result.Ciphertext;
        }
    }
}
