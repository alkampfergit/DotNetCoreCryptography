using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using DotNetCoreCryptographyCore;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptography.Azure
{
    public class AzureKeyVaultStoreKeyEncryptor : IKeyEncryptor
    {
        private readonly string _actualKeyName;
        private readonly KeyClient _keyClient;

        public AzureKeyVaultStoreKeyEncryptor(
            string keyValueStoreAddress,
            string actualKeyName)
        {
            _keyClient = new KeyClient(new Uri(keyValueStoreAddress), new DefaultAzureCredential());
            _actualKeyName = actualKeyName;
        }

        public async Task<EncryptionKey> DecryptAsync(byte[] encryptedKey)
        {
            var key = await _keyClient.GetKeyAsync(_actualKeyName);
            var cryptoClient = new CryptographyClient(keyId: key.Value.Id, credential: new DefaultAzureCredential());

            var result = await cryptoClient.DecryptAsync(
                EncryptionAlgorithm.RsaOaep256,
                encryptedKey,
                default).ConfigureAwait(false);
            try
            {
                //CreateFromSerializedVersion copies the material into the key, so the
                //plaintext DEK returned by Key Vault can be wiped afterwards (SEC-8).
                return EncryptionKey.CreateFromSerializedVersion(result.Plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(result.Plaintext);
            }
        }

        public async Task<byte[]> EncryptAsync(EncryptionKey key)
        {
            var keyVaultKey = await _keyClient.GetKeyAsync(_actualKeyName).ConfigureAwait(false);
            var cryptoClient = new CryptographyClient(keyId: keyVaultKey.Value.Id, credential: new DefaultAzureCredential());

            var serializedKey = key.Serialize();
            EncryptResult result;
            try
            {
                result = await cryptoClient.EncryptAsync(
                    EncryptionAlgorithm.RsaOaep256,
                    serializedKey,
                    default).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serializedKey);
            }
            return result.Ciphertext;
        }
    }
}
