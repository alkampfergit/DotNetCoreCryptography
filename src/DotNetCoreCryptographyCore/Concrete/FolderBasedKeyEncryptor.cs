using DotNetCoreCryptographyCore.Utils;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore.Concrete
{
    /// <summary>
    /// Simple and stupid key value store that encrypt with AES using a folder
    /// as key material storage. All keys are stored in the given location but
    /// protected with a password.
    /// </summary>
    public class FolderBasedKeyEncryptor : IKeyEncryptor
    {
        private readonly ConcurrentDictionary<int, EncryptionKey> _keys = new();
        private EncryptionKey _currentKey;
        private readonly string _keyMaterialFolderStore;
        private readonly string _password;
        private readonly KeyInformation _keyInformation;

        public FolderBasedKeyEncryptor(
            string keyMaterialFolderStore,
            string password)
        {
            _keyMaterialFolderStore = keyMaterialFolderStore;
            _password = password;
            InternalUtils.EnsureDirectory(_keyMaterialFolderStore);

            _keyInformation = LoadInfo();
            if (_keyInformation.ActualKeyNumber == 0)
            {
                GenerateNewKey();
            }
            else
            {
                _currentKey = GetKey(_keyInformation.ActualKeyNumber);
            }
        }

        private EncryptionKey GetKey(int keyNumber)
        {
            if (!_keys.TryGetValue(keyNumber, out var key))
            {
                var keyName = Path.Combine(_keyMaterialFolderStore, $"{keyNumber}.key");
                var encryptedSerializedKey = File.ReadAllBytes(keyName);
                var serializedKey = StaticEncryptor.AesDecryptWithPasswordAsync(encryptedSerializedKey, _password).Result;
                key = EncryptionKey.CreateFromSerializedVersion(serializedKey);
                _keys[keyNumber] = key;
            }
            return key;
        }

        public async Task<EncryptionKey> DecryptAsync(byte[] encryptedKey)
        {
            using var sourceMs = new MemoryStream(encryptedKey);
            var buffer = new byte[4];
            sourceMs.Read(buffer, 0, 4);
            var decryptionKey = GetKey(BitConverter.ToInt32(buffer));
            using var destinationMs = new MemoryStream();
            await StaticEncryptor.DecryptAsync(sourceMs, destinationMs, decryptionKey).ConfigureAwait(false);
            return EncryptionKey.CreateFromSerializedVersion(destinationMs.ToArray());
        }

        public async Task<byte[]> EncryptAsync(EncryptionKey key)
        {
            using var destinationMs = new MemoryStream();
            destinationMs.Write(BitConverter.GetBytes(_keyInformation.ActualKeyNumber));
            using var sourceMs = new MemoryStream(key.Serialize());

            //we need to generate another IV to avoid encrypting always with the very same value.
            await StaticEncryptor.EncryptAsync(sourceMs, destinationMs, _currentKey).ConfigureAwait(false);
            return destinationMs.ToArray();
        }

        /// <summary>
        /// Generates another key files, useful if you want to avoid using the very
        /// same key to encrypt everything and you want to change actual key.
        /// </summary>
        public void GenerateNewKey()
        {
            _keyInformation.ActualKeyNumber++;
            var keyName = Path.Combine(_keyMaterialFolderStore, $"{_keyInformation.ActualKeyNumber}.key");
            _currentKey = EncryptionKey.CreateDefault();
            _keys[_keyInformation.ActualKeyNumber] = _currentKey;
            var serializedKey = _currentKey.Serialize();
            var encryptedSerializedKey = StaticEncryptor.AesEncryptWithPasswordAsync(serializedKey, _password).Result;
            File.WriteAllBytes(keyName, encryptedSerializedKey);
            SaveInfo(_keyInformation);
        }

        private KeyInformation LoadInfo()
        {
            var infoFile = GetInfoFileName;
            if (File.Exists(infoFile))
            {
                return JsonSerializer.Deserialize<KeyInformation>(File.ReadAllText(infoFile));
            }

            return new KeyInformation();
        }

        private void SaveInfo(KeyInformation information)
        {
            File.WriteAllText(GetInfoFileName, JsonSerializer.Serialize(information));
        }

        private string GetInfoFileName => Path.Combine(_keyMaterialFolderStore, "info.json");

        private class KeyInformation
        {
            public int ActualKeyNumber { get; set; }
        }
    }
}
