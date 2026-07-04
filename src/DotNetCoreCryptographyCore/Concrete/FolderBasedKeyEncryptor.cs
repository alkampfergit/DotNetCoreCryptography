using DotNetCoreCryptographyCore.Utils;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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
            : this(keyMaterialFolderStore, password, allowUnencryptedKeys: false)
        {
        }

        /// <param name="keyMaterialFolderStore">Folder that stores the key files and metadata.</param>
        /// <param name="password">Password used to encrypt the key files at rest. When
        /// null or empty the key files are stored in cleartext.</param>
        /// <param name="allowUnencryptedKeys">Must be <c>true</c> to permit cleartext
        /// (passwordless) storage; otherwise an empty password throws.</param>
        public FolderBasedKeyEncryptor(
            string keyMaterialFolderStore,
            string password,
            bool allowUnencryptedKeys)
        {
            if (string.IsNullOrEmpty(password) && !allowUnencryptedKeys)
            {
                throw new InvalidOperationException(
                    "FolderBasedKeyEncryptor stores key files in cleartext when no password is " +
                    "provided. Provide a password, or pass allowUnencryptedKeys: true to " +
                    "acknowledge cleartext key storage.");
            }

            _keyMaterialFolderStore = keyMaterialFolderStore;
            _password = password;

            if (string.IsNullOrEmpty(password))
            {
                Trace.TraceWarning(
                    "FolderBasedKeyEncryptor is storing key files in cleartext in '{0}' because no " +
                    "password was provided; anyone who can read the folder holds the keys.",
                    keyMaterialFolderStore);
            }

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
                InternalUtils.EnsureOwnerOnlyPermissions(keyName);
                var encryptedSerializedKey = File.ReadAllBytes(keyName);
                var serializedKey = Decrypt(encryptedSerializedKey);
                key = EncryptionKey.CreateFromSerializedVersion(serializedKey);
                _keys[keyNumber] = key;
            }
            return key;
        }

        public async Task<EncryptionKey> DecryptAsync(byte[] encryptedKey)
        {
            ArgumentNullException.ThrowIfNull(encryptedKey);
            try
            {
                if (CryptoFormat.StartsWithV2Magic(encryptedKey))
                {
                    //v2 blob: [magic][int32 key-number][AES-KWP(serialized key)].
                    //RFC 5649 unwrapping is integrity-checked and fails closed on tampering.
                    var keyNumber = BinaryPrimitives.ReadInt32LittleEndian(
                        encryptedKey.AsSpan(CryptoFormat.MagicLength));
                    using var kek = CryptoFormat.CreateKeyWrapAes(GetKey(keyNumber));
                    var serializedKey = kek.DecryptKeyWrapPadded(
                        encryptedKey.AsSpan(CryptoFormat.MagicLength + sizeof(int)));
                    return EncryptionKey.CreateFromSerializedVersion(serializedKey);
                }

                //legacy v1 blob: [int32 key-number][AES-CBC(serialized key)]. A collision
                //with the v2 magic is impossible because it would require ~37.9 million
                //generated keys in the folder.
                var legacyKeyNumber = BinaryPrimitives.ReadInt32LittleEndian(encryptedKey);
                var decryptionKey = GetKey(legacyKeyNumber);
                using var sourceMs = new MemoryStream(encryptedKey, sizeof(int), encryptedKey.Length - sizeof(int));
                using var destinationMs = new MemoryStream();
                await decryptionKey.DecryptAsync(sourceMs, destinationMs).ConfigureAwait(false);
                return EncryptionKey.CreateFromSerializedVersion(destinationMs.ToArray());
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }

        public Task<byte[]> EncryptAsync(EncryptionKey key)
        {
            //v2 blob: [magic][int32 key-number][AES-KWP(serialized key)]. RFC 5649
            //key wrapping has integrity built in, so a tampered blob fails to unwrap.
            var serializedKey = key.Serialize();
            try
            {
                using var kek = CryptoFormat.CreateKeyWrapAes(_currentKey);
                var wrapped = kek.EncryptKeyWrapPadded(serializedKey);

                var blob = new byte[CryptoFormat.MagicLength + sizeof(int) + wrapped.Length];
                CryptoFormat.V2Magic.CopyTo(blob, 0);
                BinaryPrimitives.WriteInt32LittleEndian(
                    blob.AsSpan(CryptoFormat.MagicLength),
                    _keyInformation.ActualKeyNumber);
                wrapped.CopyTo(blob, CryptoFormat.MagicLength + sizeof(int));
                return Task.FromResult(blob);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serializedKey);
            }
        }

        /// <summary>
        /// Generates another key files, useful if you want to avoid using the very
        /// same key to encrypt everything and you want to change actual key.
        /// </summary>
        public void GenerateNewKey()
        {
            // Serialize the whole generate-and-persist sequence so two concurrent
            // callers cannot pick the same key number and clobber each other's file.
            lock (_lock)
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
                try
                {
                    var encryptedSerializedKey = Encrypt(serializedKey);
                    // CreateNew + owner-only perms: never silently overwrite an existing
                    // key file, and never leave it group/world-readable.
                    InternalUtils.WriteNewFileRestricted(keyName, encryptedSerializedKey);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(serializedKey);
                }
                SaveInfo(_keyInformation);
            }
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
                var json = JsonSerializer.Serialize(information);
                InternalUtils.WriteFileRestricted(GetInfoFileName, Encoding.UTF8.GetBytes(json));
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
