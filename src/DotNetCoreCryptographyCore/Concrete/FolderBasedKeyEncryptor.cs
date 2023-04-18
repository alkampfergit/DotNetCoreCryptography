using DotNetCoreCryptographyCore.Utils;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
        private readonly ConcurrentDictionary<int, EncryptionKey> _keys = new ConcurrentDictionary<int, EncryptionKey>();
        private EncryptionKey _currentKey;
        private readonly string _keyMaterialFolderStore;

        private readonly object _lock = new object();

        /// <summary>
        /// If different from empty, will be used to encrypt keys
        /// that are stored inside the shared folder.
        /// </summary>
        private readonly string _password;
        private readonly KeysDatabase _keyInformation;

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

        private bool KeysAreEncrpted => !string.IsNullOrEmpty(_password);

        private byte[] Encrypt(byte[] key)
        {
            if (!String.IsNullOrEmpty(_password))
            {
                //use a static shared password to encrypt the data
                return StaticEncryptor.AesEncryptWithPassword(key, _password);
            }

            //Key is unencrypted
            return key;
        }

        private byte[] Decrypt(byte[] key)
        {
            if (!String.IsNullOrEmpty(_password))
            {
                //use a static shared password to decrypt the data
                return StaticEncryptor.AesDecryptWithPassword(key, _password);
            }

            //Key is unencrypted
            return key;
        }

        private EncryptionKey GetKey(int keyNumber)
        {
            if (!_keys.TryGetValue(keyNumber, out var key))
            {
                var keyName = Path.Combine(_keyMaterialFolderStore, $"{keyNumber}.key");
                var encryptedSerializedKey = File.ReadAllBytes(keyName);
                var serializedKey = Decrypt(encryptedSerializedKey);
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
            _keyInformation.ActualKeyNumber += 1;
            var keyName = Path.Combine(_keyMaterialFolderStore, $"{_keyInformation.ActualKeyNumber}.key");
            _currentKey = EncryptionKey.CreateDefault();
            _keys[_keyInformation.ActualKeyNumber] = _currentKey;
            _keyInformation.KeysInformation[_keyInformation.ActualKeyNumber.ToString()] = new KeyInformation()
            {
                Id = _keyInformation.ActualKeyNumber.ToString(),
                Encrypted = KeysAreEncrpted,
                CreatonDate = DateTime.UtcNow,
                Revoked = false,
            };

            var serializedKey = _currentKey.Serialize();
            var encryptedSerializedKey = Encrypt(serializedKey);
            File.WriteAllBytes(keyName, encryptedSerializedKey);
            SaveInfo(_keyInformation);
        }

        private KeysDatabase LoadInfo()
        {
            var infoFile = GetInfoFileName;
            if (File.Exists(infoFile))
            {
                return JsonSerializer.Deserialize<KeysDatabase>(File.ReadAllText(infoFile));
            }

            return new KeysDatabase();
        }

        private void SaveInfo(KeysDatabase information)
        {
            lock (_lock)
            {
                File.WriteAllText(GetInfoFileName, JsonSerializer.Serialize(information));
            }
        }

        private string GetInfoFileName => Path.Combine(_keyMaterialFolderStore, "info.json");

        private class KeysDatabase
        {
            public int ActualKeyNumber { get; set; }

            public Dictionary<string, KeyInformation> KeysInformation { get; set; } = new Dictionary<string, KeyInformation>();
        }

        private class KeyInformation
        {
            public string Id { get; set; }

            public Boolean Encrypted { get; set; }
            public DateTime CreatonDate { get; internal set; }
            public bool Revoked { get; internal set; }
        }
    }
}
