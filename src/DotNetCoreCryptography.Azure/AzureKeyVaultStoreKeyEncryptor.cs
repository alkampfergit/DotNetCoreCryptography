using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using DotNetCoreCryptographyCore;
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCoreCryptography.Azure
{
    /// <summary>
    /// Wraps a data key with an RSA key stored in Azure Key Vault.
    /// <para>
    /// The wrapped-key blob stores the exact Key Vault key <em>version</em> that
    /// produced the ciphertext, so a blob keeps decrypting after the vault key is
    /// rotated (rotation creates a new default version; the old version stays
    /// enabled). Older blobs written before this hardening carry only the RSA
    /// ciphertext and are decrypted with the current default version for backward
    /// compatibility.
    /// </para>
    /// </summary>
    public class AzureKeyVaultStoreKeyEncryptor : IKeyEncryptor
    {
        /// <summary>"DNC" + 0x20: marks the versioned wrapped-key format. Legacy blobs
        /// are raw RSA-OAEP ciphertext (effectively random bytes), so they collide
        /// with this magic only with probability 2^-32; a false match simply fails to
        /// parse and decryption fails, so the scheme stays fail-closed.</summary>
        private static readonly byte[] BlobMagic = { 0x44, 0x4E, 0x43, 0x20 };
        private const int MagicLength = 4;

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
            ArgumentNullException.ThrowIfNull(encryptedKey);

            byte[] ciphertext;
            CryptographyClient cryptoClient;
            if (StartsWithMagic(encryptedKey))
            {
                // Versioned blob: [magic][ushort keyIdLength][UTF-8 key id][RSA ciphertext].
                // Decrypt with the exact key version recorded at encryption time.
                var keyId = ParseVersionedBlob(encryptedKey, out ciphertext);
                // The key id comes from the (unauthenticated) blob, so restrict it to
                // the configured vault and key name: a tampered blob must not be able
                // to redirect decryption to an arbitrary vault/key URI. Only the
                // version segment may vary (that is the whole point of the versioning).
                EnsureKeyUriMatchesConfiguration(keyId);
                cryptoClient = new CryptographyClient(keyId, new DefaultAzureCredential());
            }
            else
            {
                // Legacy blob: raw RSA ciphertext, decrypted with the current default
                // version (the pre-hardening behavior).
                var key = await _keyClient.GetKeyAsync(_actualKeyName).ConfigureAwait(false);
                ciphertext = encryptedKey;
                cryptoClient = new CryptographyClient(keyId: key.Value.Id, credential: new DefaultAzureCredential());
            }

            var result = await cryptoClient.DecryptAsync(
                EncryptionAlgorithm.RsaOaep256,
                ciphertext,
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
            // key.Value.Id is the versioned key URI; recording it lets DecryptAsync
            // pick the exact version even after the vault key is rotated.
            var keyId = keyVaultKey.Value.Id;
            var cryptoClient = new CryptographyClient(keyId: keyId, credential: new DefaultAzureCredential());

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

            return BuildVersionedBlob(keyId.AbsoluteUri, result.Ciphertext);
        }

        /// <summary>
        /// Verifies that a key URI taken from a wrapped-key blob points at the vault
        /// and key this encryptor is configured for. Scheme, host and port must match
        /// the configured vault and the path must be <c>/keys/{configuredKeyName}[/{version}]</c>;
        /// only the version may differ. Fails closed with <see cref="CryptographicException"/>.
        /// </summary>
        internal void EnsureKeyUriMatchesConfiguration(Uri keyId)
        {
            var vault = _keyClient.VaultUri;
            bool sameVault =
                string.Equals(keyId.Scheme, vault.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(keyId.Host, vault.Host, StringComparison.OrdinalIgnoreCase)
                && keyId.Port == vault.Port;

            // AbsolutePath is "/keys/{name}" or "/keys/{name}/{version}".
            var segments = keyId.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            bool sameKey =
                segments.Length >= 2
                && segments.Length <= 3
                && string.Equals(segments[0], "keys", StringComparison.OrdinalIgnoreCase)
                && string.Equals(segments[1], _actualKeyName, StringComparison.Ordinal);

            if (!sameVault || !sameKey)
            {
                throw new CryptographicException(
                    "Wrapped key references a Key Vault key that does not match the configured vault/key.");
            }
        }

        private static bool StartsWithMagic(byte[] data)
        {
            return data.Length >= MagicLength
                && data.AsSpan(0, MagicLength).SequenceEqual(BlobMagic);
        }

        internal static byte[] BuildVersionedBlob(string keyId, byte[] ciphertext)
        {
            var keyIdBytes = Encoding.UTF8.GetBytes(keyId);
            if (keyIdBytes.Length > ushort.MaxValue)
            {
                // A Key Vault key URI is well under 64 KiB; this only guards the
                // length field against an unexpected input.
                throw new CryptographicException("Key Vault key id is too long to store.");
            }

            var blob = new byte[MagicLength + sizeof(ushort) + keyIdBytes.Length + ciphertext.Length];
            BlobMagic.CopyTo(blob, 0);
            BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(MagicLength), (ushort)keyIdBytes.Length);
            keyIdBytes.CopyTo(blob, MagicLength + sizeof(ushort));
            ciphertext.CopyTo(blob, MagicLength + sizeof(ushort) + keyIdBytes.Length);
            return blob;
        }

        internal static Uri ParseVersionedBlob(byte[] blob, out byte[] ciphertext)
        {
            if (blob.Length < MagicLength + sizeof(ushort))
            {
                throw new CryptographicException("Malformed Azure wrapped key blob.");
            }
            int keyIdLength = BinaryPrimitives.ReadUInt16BigEndian(blob.AsSpan(MagicLength));
            int ciphertextOffset = MagicLength + sizeof(ushort) + keyIdLength;
            if (blob.Length <= ciphertextOffset)
            {
                throw new CryptographicException("Malformed Azure wrapped key blob.");
            }

            var keyId = Encoding.UTF8.GetString(blob, MagicLength + sizeof(ushort), keyIdLength);
            // Fail closed with the same exception type as every other malformed-blob
            // case instead of letting the Uri constructor throw UriFormatException.
            if (!Uri.TryCreate(keyId, UriKind.Absolute, out var keyUri))
            {
                throw new CryptographicException("Malformed Azure wrapped key blob.");
            }

            ciphertext = blob[ciphertextOffset..];
            return keyUri;
        }
    }
}
