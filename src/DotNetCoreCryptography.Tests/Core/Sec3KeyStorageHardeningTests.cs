using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    /// <summary>
    /// Tests for the SEC-3 key-storage hardening: restrictive file/directory
    /// permissions on Unix, atomic race-free key creation, the opt-in required for
    /// cleartext storage, and DPAPI protection of the developer key on Windows.
    /// Behavior deliberately differs by platform, so several tests only assert on
    /// the platform they target and no-op elsewhere (both are exercised in CI).
    /// </summary>
    public class Sec3KeyStorageHardeningTests
    {
        // "DNC" + 'P': the marker the developer key file carries when its payload is
        // DPAPI-protected. Kept in sync with DeveloperKeyEncryptor.DpapiMagic.
        private static readonly byte[] DpapiMagic = { 0x44, 0x4E, 0x43, 0x50 };

        private const UnixFileMode GroupOrOtherAccess =
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

        private static string NewTempFolder() =>
            Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());

        [Fact]
        public void Developer_store_on_unix_requires_explicit_opt_in()
        {
            if (OperatingSystem.IsWindows())
            {
                // On Windows the key is DPAPI-protected, so no opt-in is needed.
                return;
            }

            Assert.Throws<InvalidOperationException>(
                () => new DeveloperKeyEncryptor(NewTempFolder()));
        }

        [Fact]
        public async Task Developer_key_file_and_folder_are_owner_only_on_unix()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var folder = NewTempFolder();
            using var key = new AesEncryptionKey();
            var sut = new DeveloperKeyEncryptor(folder, allowUnencryptedKeyStore: true);
            // Force the key file to be written.
            await sut.EncryptAsync(key);

            var keyFile = Path.Combine(folder, DeveloperKeyEncryptor.DeveloperKeyName);
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(keyFile));
            Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(folder) & GroupOrOtherAccess);
        }

        [Fact]
        public async Task Loosened_developer_key_permissions_are_tightened_on_read()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var folder = NewTempFolder();
            using var key = new AesEncryptionKey();
            var first = new DeveloperKeyEncryptor(folder, allowUnencryptedKeyStore: true);
            var encrypted = await first.EncryptAsync(key);

            var keyFile = Path.Combine(folder, DeveloperKeyEncryptor.DeveloperKeyName);
            // Simulate a key file created before the hardening: world/group readable.
            File.SetUnixFileMode(
                keyFile,
                UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.GroupRead | UnixFileMode.OtherRead);

            // Opening a new instance must still read the key and tighten the mode.
            var second = new DeveloperKeyEncryptor(folder, allowUnencryptedKeyStore: true);
            var decrypted = await second.DecryptAsync(encrypted);
            Assert.Equal(key, decrypted);
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(keyFile));
        }

        [Fact]
        public async Task Concurrent_developer_encryptor_construction_does_not_lose_key()
        {
            // All instances race to create the single key file; the atomic CreateNew
            // write plus re-read must leave every instance holding the same key, so a
            // blob encrypted by one decrypts with any other.
            var folder = NewTempFolder();

            var instances = await Task.WhenAll(
                Enumerable.Range(0, 16).Select(_ => Task.Run(
                    () => new DeveloperKeyEncryptor(folder, allowUnencryptedKeyStore: true))));

            using var payload = EncryptionKey.CreateDefault();
            var encrypted = await instances[0].EncryptAsync(payload);

            foreach (var instance in instances)
            {
                using var decrypted = await instance.DecryptAsync(encrypted);
                Assert.Equal(payload, decrypted);
            }

            Assert.Single(Directory.GetFiles(folder, DeveloperKeyEncryptor.DeveloperKeyName));
        }

        [Fact]
        public async Task Developer_key_is_dpapi_protected_on_windows()
        {
            if (!OperatingSystem.IsWindows())
            {
                return;
            }

            var folder = NewTempFolder();
            using var key = new AesEncryptionKey();
            var sut = new DeveloperKeyEncryptor(folder);
            var encrypted = await sut.EncryptAsync(key);

            // The persisted file must be DPAPI-wrapped, not the raw serialized key.
            var keyFile = Path.Combine(folder, DeveloperKeyEncryptor.DeveloperKeyName);
            var onDisk = await File.ReadAllBytesAsync(keyFile);
            Assert.True(onDisk.Take(DpapiMagic.Length).SequenceEqual(DpapiMagic));

            // A fresh instance must be able to unwrap it and round-trip.
            var reopened = new DeveloperKeyEncryptor(folder);
            using var decrypted = await reopened.DecryptAsync(encrypted);
            Assert.Equal(key, decrypted);
        }

        [Fact]
        public void Folder_store_without_password_requires_explicit_opt_in()
        {
            Assert.Throws<InvalidOperationException>(
                () => new FolderBasedKeyEncryptor(NewTempFolder(), string.Empty));
            Assert.Throws<InvalidOperationException>(
                () => new FolderBasedKeyEncryptor(NewTempFolder(), null));
        }

        [Fact]
        public void Loosened_key_directory_is_tightened_on_reopen_on_unix()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var folder = NewTempFolder();
            var first = new FolderBasedKeyEncryptor(folder, "a-password");
            first.GenerateNewKey();

            // Simulate a directory created before this hardening (or by another tool)
            // with group/world access.
            File.SetUnixFileMode(
                folder,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

            // Reopening the store must detect the loose directory and tighten it.
            _ = new FolderBasedKeyEncryptor(folder, "a-password");
            Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(folder) & GroupOrOtherAccess);
        }

        [Fact]
        public void Folder_store_key_files_are_owner_only_on_unix()
        {
            if (OperatingSystem.IsWindows())
            {
                return;
            }

            var folder = NewTempFolder();
            var sut = new FolderBasedKeyEncryptor(folder, "a-password");
            sut.GenerateNewKey();

            foreach (var file in Directory.GetFiles(folder))
            {
                Assert.Equal(
                    UnixFileMode.UserRead | UnixFileMode.UserWrite,
                    File.GetUnixFileMode(file));
            }
            Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(folder) & GroupOrOtherAccess);
        }
    }
}
