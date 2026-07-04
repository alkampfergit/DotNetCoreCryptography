using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Legacy symmetric key based on AES-256-CBC. The format is <b>unauthenticated</b>:
    /// the ciphertext carries no integrity protection, so tampering cannot be
    /// detected (see security finding SEC-1). It is retained only to decrypt data
    /// written by previous versions of the library; new data should always be
    /// encrypted with <see cref="AesGcmEncryptionKey"/> /
    /// <see cref="EncryptionKey.CreateDefault"/>.
    /// </summary>
    public class AesEncryptionKey : EncryptionKey
    {
        /// <summary>
        /// Create a new <see cref="AesEncryptionKey"/>, a legacy AES-256-CBC key.
        /// </summary>
        [Obsolete("AesEncryptionKey uses unauthenticated AES-CBC and is retained only for compatibility with existing (v1) data. Use EncryptionKey.CreateDefault() / AesGcmEncryptionKey for new data.")]
        public AesEncryptionKey()
        {
            _key = Aes.Create();

            if (_key.KeySize != 256)
            {
                throw new Exception($"Generated AES key has no 256 bit length but it has {_key.KeySize} bit key");
            }
        }

        public AesEncryptionKey(byte[] serializedValue)
        {
            _key = serializedValue.DeserializeToAes();
        }

        private readonly Aes _key;

        public override void Encrypt(Stream sourceStream, Stream destinationStream, byte[] associatedData = null)
        {
            ThrowIfAssociatedDataProvided(associatedData);
            using var encryptor = CreateEncryptorCore(destinationStream);
            using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
            sourceStream.CopyTo(cryptoStream);
        }

        public override async Task EncryptAsync(Stream sourceStream, Stream destinationStream, byte[] associatedData = null)
        {
            ThrowIfAssociatedDataProvided(associatedData);
            using var encryptor = CreateEncryptorCore(destinationStream);
            var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, leaveOpen: true);
            await using (cryptoStream.ConfigureAwait(false))
            {
                await sourceStream.CopyToAsync(cryptoStream).ConfigureAwait(false);
            }
        }

        public override void Decrypt(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null)
        {
            ThrowIfAssociatedDataProvided(associatedData);
            try
            {
                using var decryptor = CreateDecryptorCore(encryptedStream);
                using var cryptoStream = new CryptoStream(encryptedStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
                cryptoStream.CopyTo(destinationStream);
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }

        public override async Task DecryptAsync(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null)
        {
            ThrowIfAssociatedDataProvided(associatedData);
            try
            {
                using var decryptor = CreateDecryptorCore(encryptedStream);
                using var cryptoStream = new CryptoStream(encryptedStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
                await cryptoStream.CopyToAsync(destinationStream).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }

        private static void ThrowIfAssociatedDataProvided(byte[] associatedData)
        {
            if (associatedData is { Length: > 0 })
            {
                throw new NotSupportedException("The legacy AES-CBC key cannot authenticate associated data.");
            }
        }

        /// <inheritdoc/>
        [Obsolete("The transform-based API produces the legacy unauthenticated AES-CBC format. Use Encrypt/EncryptAsync on an AesGcmEncryptionKey instead.")]
        public override ICryptoTransform CreateEncryptor(Stream destinationStream)
        {
            return CreateEncryptorCore(destinationStream);
        }

        /// <inheritdoc/>
        [Obsolete("The transform-based API reads the legacy unauthenticated AES-CBC format. Use Decrypt/DecryptAsync instead.")]
        public override ICryptoTransform CreateDecryptor(Stream encryptedStream)
        {
            return CreateDecryptorCore(encryptedStream);
        }

        private ICryptoTransform CreateEncryptorCore(Stream destinationStream)
        {
            using var newKey = Aes.Create();
            newKey.Key = _key.Key;
            newKey.Mode = _key.Mode;
            newKey.IV = EncryptionUtils.GenerateRandomByteArray(newKey.IV.Length);
            destinationStream.Write(newKey.IV, 0, newKey.IV.Length);
            return newKey.CreateEncryptor();
        }

        private ICryptoTransform CreateDecryptorCore(Stream encryptedStream)
        {
            using var newKey = Aes.Create();
            newKey.Key = _key.Key;
            newKey.Mode = _key.Mode;
            var newIV = new byte[newKey.IV.Length];
            encryptedStream.ReadExactly(newIV);
            newKey.IV = newIV;
            return newKey.CreateDecryptor();
        }

        public override byte[] Serialize()
        {
            return _key.Serialize();
        }

        internal override byte[] ExportRawKeyMaterial()
        {
            return _key.Key;
        }

        protected override void OnDispose(bool disposing)
        {
            if (disposing)
            {
                _key.Dispose();
            }
        }

        public override bool Equals(object obj)
        {
            if (obj is not AesEncryptionKey otherKey)
            {
                return false;
            }

            // Each Key/IV getter allocates a fresh copy of the secret; compare in
            // constant time (SEC-7) and wipe the copies afterwards (SEC-8).
            var thisKey = _key.Key;
            var otherKeyBytes = otherKey._key.Key;
            var thisIv = _key.IV;
            var otherIv = otherKey._key.IV;
            try
            {
                return _key.Mode == otherKey._key.Mode
                    && CryptographicOperations.FixedTimeEquals(thisKey, otherKeyBytes)
                    && CryptographicOperations.FixedTimeEquals(thisIv, otherIv);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(thisKey);
                CryptographicOperations.ZeroMemory(otherKeyBytes);
                CryptographicOperations.ZeroMemory(thisIv);
                CryptographicOperations.ZeroMemory(otherIv);
            }
        }

        public override int GetHashCode()
        {
            return _key.GetHashCode();
        }
    }
}
