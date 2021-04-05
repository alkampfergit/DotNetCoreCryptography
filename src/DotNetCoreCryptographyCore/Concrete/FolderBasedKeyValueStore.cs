using DotNetCoreCryptographyCore.Utils;
using System.IO;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore.Concrete
{
    /// <summary>
    /// Simple and stupid key value store that encrypt with AES using a folder
    /// as key material storage. All keys are stored in the given location but
    /// protected with a password.
    /// </summary>
    public class FolderBasedKeyValueStore : IKeyVaultStore
    {
        private readonly EncryptionKey _key;

        public FolderBasedKeyValueStore(
            string keyMaterialFolderStore,
            string password)
        {
            InternalUtils.EnsureDirectory(keyMaterialFolderStore);

            var keyName = Path.Combine(keyMaterialFolderStore, "1.key");
            if (!File.Exists(keyName))
            {
                //create the first key
                _key = EncryptionKey.CreateDefault();
                var serializedKey = _key.Serialize();
                var encryptedSerializedKey = StaticEncryptor.AesEncryptWithPasswordAsync(serializedKey, password).Result;
                File.WriteAllBytes(keyName, encryptedSerializedKey);
            }
            else
            {
                var encryptedSerializedKey = File.ReadAllBytes(keyName);
                var serializedKey = StaticEncryptor.AesDecryptWithPasswordAsync(encryptedSerializedKey, password).Result;
                _key = EncryptionKey.CreateFromSerializedVersion(serializedKey);
            }
        }

        public async Task<EncryptionKey> DecriptAsync(byte[] encryptedKey)
        {
            using var sourceMs = new MemoryStream(encryptedKey);
            using var destinationMs = new MemoryStream();
            await StaticEncryptor.DecryptAsync(sourceMs, destinationMs, _key).ConfigureAwait(false);
            return EncryptionKey.CreateFromSerializedVersion(destinationMs.ToArray());
        }

        public async Task<byte[]> EncryptAsync(EncryptionKey key)
        {
            using var destinationMs = new MemoryStream();
            using var sourceMs = new MemoryStream(key.Serialize());
            //we need to generate another IV to avoid encrypting always with the very same value.
            await StaticEncryptor.EncryptAsync(sourceMs, destinationMs, _key).ConfigureAwait(false);
            return destinationMs.ToArray();
        }
    }
}
