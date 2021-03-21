using System;
using System.IO;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore.Concrete
{
    public class FolderBasedKeyValueStore : IKeyVaultStore
    {
        private string _keyMaterialFolderStore;

        private readonly EncryptionKey _key;

        public FolderBasedKeyValueStore(
            string keyMaterialFolderStore,
            string password)
        {
            _keyMaterialFolderStore = keyMaterialFolderStore;
            if (!Directory.Exists(_keyMaterialFolderStore))
            {
                Directory.CreateDirectory(_keyMaterialFolderStore);
            }

            var keyName = Path.Combine(_keyMaterialFolderStore, "1.key");
            if (!File.Exists(keyName))
            {
                //create the first key
                _key = new EncryptionKey();
                var serializedKey = _key.Serialize();
                var encryptedSerializedKey = StaticEncryptor.AesEncryptWithPasswordAsync(serializedKey, password).Result;
                File.WriteAllBytes(keyName, encryptedSerializedKey);
            }
            else
            {
                var encryptedSerializedKey = File.ReadAllBytes(keyName);
                var serializedKey = StaticEncryptor.AesDecryptWithPasswordAsync(encryptedSerializedKey, password).Result;
                _key = new EncryptionKey(serializedKey);
            }
        }

        public async Task<EncryptionKey> DecriptAsync(byte[] encryptedKey)
        {
            using var sourceMs = new MemoryStream(encryptedKey);
            using var destinationMs = new MemoryStream();
            await StaticEncryptor.DecryptAsync(sourceMs, destinationMs, _key).ConfigureAwait(false);
            return new EncryptionKey(destinationMs.ToArray());
        }

        public async Task<byte[]> EncryptAsync(EncryptionKey key)
        {
            using var destinationMs = new MemoryStream();
            using var sourceMs = new MemoryStream(key.Serialize());
            await StaticEncryptor.EncryptAsync(sourceMs, destinationMs, _key).ConfigureAwait(false);
            return destinationMs.ToArray();
        }
    }
}
