using DotNetCoreCryptographyCore.Utils;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore.Concrete
{
    /// <summary>
    /// A simple implementation of a key store meant for developer machines rather
    /// than production. It keeps a single master key in a folder on disk.
    /// <para>
    /// On Windows the master key is encrypted at rest with DPAPI
    /// (<see cref="ProtectedData"/>, current-user scope). On non-Windows platforms
    /// DPAPI is unavailable, so the key is stored in cleartext and the caller must
    /// explicitly acknowledge that by passing <c>allowUnencryptedKeyStore: true</c>;
    /// otherwise construction throws.
    /// </para>
    /// </summary>
    public class DeveloperKeyEncryptor : IKeyEncryptor
    {
        public const string DeveloperKeyName = "developerKeyValueStore.key";

        /// <summary>
        /// Marks a key file whose payload is DPAPI-protected: "DNC" + 'P'. A raw
        /// serialized key can never start with this sequence because its first byte
        /// is a <see cref="KeyType"/> (0 or 1), so the two formats are unambiguous.
        /// </summary>
        private static readonly byte[] DpapiMagic = { 0x44, 0x4E, 0x43, 0x50 };

        private readonly EncryptionKey _key;

        public DeveloperKeyEncryptor(string keyFolder)
            : this(keyFolder, allowUnencryptedKeyStore: false)
        {
        }

        /// <param name="keyFolder">Folder that stores the master key file.</param>
        /// <param name="allowUnencryptedKeyStore">On non-Windows platforms the master
        /// key is stored in cleartext (no DPAPI); pass <c>true</c> to acknowledge and
        /// allow that. Ignored on Windows, where the key is always DPAPI-protected.</param>
        public DeveloperKeyEncryptor(string keyFolder, bool allowUnencryptedKeyStore)
        {
            InternalUtils.EnsureDirectory(keyFolder);
            var keyName = Path.Combine(keyFolder, DeveloperKeyName);

            if (!OperatingSystem.IsWindows() && !allowUnencryptedKeyStore)
            {
                throw new InvalidOperationException(
                    "DeveloperKeyEncryptor stores its master key in cleartext on non-Windows " +
                    "platforms because DPAPI is unavailable. Pass allowUnencryptedKeyStore: true " +
                    "to acknowledge this, or use a production-grade key store.");
            }

            _key = LoadOrCreateKey(keyName);
        }

        private static EncryptionKey LoadOrCreateKey(string keyName)
        {
            if (!File.Exists(keyName))
            {
                try
                {
                    CreateKey(keyName);
                }
                catch (IOException)
                {
                    // Lost the creation race: another process created the file between
                    // the File.Exists check and the atomic CreateNew write. Fall through
                    // and read the key that the winner wrote.
                }
            }

            return ReadKey(keyName);
        }

        private static void CreateKey(string keyName)
        {
            using var key = EncryptionKey.CreateDefault();
            var serializedKey = key.Serialize();
            try
            {
                var payload = OperatingSystem.IsWindows()
                    ? ProtectWithDpapi(serializedKey)
                    : serializedKey;
                InternalUtils.WriteNewFileRestricted(keyName, payload);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serializedKey);
            }
        }

        private static EncryptionKey ReadKey(string keyName)
        {
            // On Unix the key is cleartext; make sure it is not world/group readable
            // (and tighten it if a legacy/looser file is found).
            InternalUtils.EnsureOwnerOnlyPermissions(keyName);

            var raw = File.ReadAllBytes(keyName);
            if (StartsWithDpapiMagic(raw))
            {
                if (!OperatingSystem.IsWindows())
                {
                    throw new PlatformNotSupportedException(
                        "This developer key file is DPAPI-protected and can only be read on Windows.");
                }

                var serializedKey = UnprotectWithDpapi(raw);
                try
                {
                    return EncryptionKey.CreateFromSerializedVersion(serializedKey);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(serializedKey);
                }
            }

            // Legacy cleartext file (written before this hardening or on a non-Windows
            // host). Still supported for backward compatibility.
            if (OperatingSystem.IsWindows())
            {
                Trace.TraceWarning(
                    "Developer key file '{0}' is stored in cleartext. Delete it to have a new, " +
                    "DPAPI-protected key generated on next use.",
                    keyName);
            }

            return EncryptionKey.CreateFromSerializedVersion(raw);
        }

        private static bool StartsWithDpapiMagic(byte[] data)
        {
            return data.Length >= DpapiMagic.Length
                && data.AsSpan(0, DpapiMagic.Length).SequenceEqual(DpapiMagic);
        }

        [SupportedOSPlatform("windows")]
        private static byte[] ProtectWithDpapi(byte[] serializedKey)
        {
            var protectedBytes = ProtectedData.Protect(serializedKey, null, DataProtectionScope.CurrentUser);
            var blob = new byte[DpapiMagic.Length + protectedBytes.Length];
            DpapiMagic.CopyTo(blob, 0);
            protectedBytes.CopyTo(blob, DpapiMagic.Length);
            return blob;
        }

        [SupportedOSPlatform("windows")]
        private static byte[] UnprotectWithDpapi(byte[] blob)
        {
            var protectedBytes = blob.AsSpan(DpapiMagic.Length).ToArray();
            return ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
        }

        public async Task<EncryptionKey> DecryptAsync(byte[] encryptedKey)
        {
            ArgumentNullException.ThrowIfNull(encryptedKey);
            try
            {
                if (CryptoFormat.StartsWithV2Magic(encryptedKey))
                {
                    //v2 blob: [magic][AES-KWP(serialized key)]. RFC 5649 unwrapping is
                    //integrity-checked and fails closed on tampering. Note: a legacy v1
                    //blob starts with a random IV, so it can begin with the magic with
                    //probability 2^-32; such a blob would fail here instead of being
                    //routed to the legacy path (fail closed by design).
                    using var kek = CryptoFormat.CreateKeyWrapAes(_key);
                    var serializedKey = kek.DecryptKeyWrapPadded(
                        encryptedKey.AsSpan(CryptoFormat.MagicLength));
                    try
                    {
                        //CreateFromSerializedVersion copies the material, so the
                        //transient plaintext DEK can be wiped afterwards (SEC-8).
                        return EncryptionKey.CreateFromSerializedVersion(serializedKey);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(serializedKey);
                    }
                }

                //legacy v1 blob: [16-byte IV][AES-CBC(serialized key)]
                using var sourceMs = new MemoryStream(encryptedKey);
                using var destinationMs = new MemoryStream();
                await _key.DecryptAsync(sourceMs, destinationMs).ConfigureAwait(false);
                var legacySerializedKey = destinationMs.ToArray();
                try
                {
                    return EncryptionKey.CreateFromSerializedVersion(legacySerializedKey);
                }
                finally
                {
                    //Wipe both the copy and the stream's own backing buffer: disposing
                    //the MemoryStream does not clear its internal plaintext (SEC-8).
                    CryptographicOperations.ZeroMemory(legacySerializedKey);
                    CryptographicOperations.ZeroMemory(destinationMs.GetBuffer().AsSpan(0, (int)destinationMs.Length));
                }
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }

        public Task<byte[]> EncryptAsync(EncryptionKey key)
        {
            //v2 blob: [magic][AES-KWP(serialized key)]
            var serializedKey = key.Serialize();
            try
            {
                using var kek = CryptoFormat.CreateKeyWrapAes(_key);
                var wrapped = kek.EncryptKeyWrapPadded(serializedKey);

                var blob = new byte[CryptoFormat.MagicLength + wrapped.Length];
                CryptoFormat.V2Magic.CopyTo(blob, 0);
                wrapped.CopyTo(blob, CryptoFormat.MagicLength);
                return Task.FromResult(blob);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serializedKey);
            }
        }
    }
}
