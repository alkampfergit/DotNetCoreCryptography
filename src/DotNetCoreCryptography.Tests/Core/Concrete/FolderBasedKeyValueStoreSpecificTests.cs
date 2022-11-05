using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core.Concrete
{
    /// <summary>
    /// Still not to be used in production, it implements a simple key
    /// vault store that is based on a folder on disk. Key is encrypted
    /// with a secret password that should be given into constructor
    /// to decrypt the key from disk.
    /// </summary>
    public class FolderBasedKeyValueStoreSpecificTests : IDisposable
    {
        private string _keyMaterialFolder;
        private string _databaseFile;

        private FolderBasedKeyEncryptor GenerateSut(string password = "password")
        {
            _keyMaterialFolder = Path.GetTempPath() + Guid.NewGuid().ToString();
            _databaseFile = Path.Combine(_keyMaterialFolder, "info.json");
            return new FolderBasedKeyEncryptor(
                _keyMaterialFolder,
                password);
        }

        [Fact]
        public async Task Unable_to_decrypt_if_wrong_password()
        {
            using var key = new AesEncryptionKey();
            var sut = GenerateSut();
            await sut.EncryptAsync(key).ConfigureAwait(false);

            //We should not be able to create a sut where already exists a key
            //with an invalid password
            Assert.Throws<CryptographicException>(() => new FolderBasedKeyEncryptor(
               _keyMaterialFolder,
               "another-password"));
        }

        [Fact]
        public async Task Verify_internal_database()
        {
            GenerateSut();
            var dbFileContent = await File.ReadAllTextAsync(_databaseFile);
            var deserialized = JsonConvert.DeserializeObject<KeysDatabase>(dbFileContent);
            Assert.True(deserialized.KeysInformation.ContainsKey("1"));
            var info = deserialized.KeysInformation["1"];
            Assert.False(info.Revoked);
            Assert.True(info.Encrypted);
        }

        [Fact]
        public async Task Verify_can_use_unencrypted_folder_storage()
        {
            GenerateSut("");
            var dbFileContent = await File.ReadAllTextAsync(_databaseFile);
            var deserialized = JsonConvert.DeserializeObject<KeysDatabase>(dbFileContent);
            Assert.True(deserialized.KeysInformation.ContainsKey("1"));
            var info = deserialized.KeysInformation["1"];
            Assert.False(info.Revoked);

            //this is the real test, we have unencrypted keys.
            Assert.False(info.Encrypted);
        }

        [Fact]
        public async Task Avoid_using_the_same_IV()
        {
            using var key = new AesEncryptionKey();
            var sut = GenerateSut();
            await sut.EncryptAsync(key).ConfigureAwait(false);

            //We will encrypt with the very same key the very same key.
            var encrypted = await sut.EncryptAsync(key).ConfigureAwait(false);
            var otherEncrypted = await sut.EncryptAsync(key).ConfigureAwait(false);

            //Same key encrypted two times should generate a different result due to different IV used
            Assert.NotEqual(encrypted, otherEncrypted);
        }

        [Fact]
        public void Auto_create_first_key()
        {
            GenerateSut();

            Assert.Single(Directory.GetFiles(_keyMaterialFolder, "*.key"));
        }

        [Fact]
        public void Basic_ability_to_rotate_key()
        {
            var sut = GenerateSut();

            sut.GenerateNewKey();
            Assert.Equal(2, Directory.GetFiles(_keyMaterialFolder, "*.key").Length);
        }

        [Fact]
        public async Task Rotate_and_decrypt()
        {
            using var key = EncryptionKey.CreateDefault();
            var sut = GenerateSut();

            var encrypted = await sut.EncryptAsync(key).ConfigureAwait(false);

            //We generate a new key, but we are able to decrypt old key.
            sut.GenerateNewKey();
            var decrypted = await sut.DecryptAsync(encrypted).ConfigureAwait(false);
            Assert.Equal(key, decrypted);
        }

        public void Dispose()
        {
            if (Directory.Exists(_keyMaterialFolder))
            {
                Directory.Delete(_keyMaterialFolder, true);
            }
        }
    }

    internal class KeysDatabase
    {
        public int ActualKeyNumber { get; set; }

        public Dictionary<string, KeyInformation> KeysInformation { get; set; } = new Dictionary<string, KeyInformation>();
    }

    internal class KeyInformation
    {
        public string Id { get; set; }

        public Boolean Encrypted { get; set; }
        public DateTime CreatonDate { get; internal set; }
        public bool Revoked { get; internal set; }
    }
}
