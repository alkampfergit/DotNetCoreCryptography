using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Wrap an implementation of an encryption key, simmetric, this
    /// is done to avoid hardcoding AES all the way up the user.
    /// </summary>
    /// <remarks>This is an implementation of a symmetric key.</remarks>
    public class AesEncryptionKey : EncryptionKey
    {
        /// <summary>
        /// Create a new <see cref="AesEncryptionKey"/> with the standard configured
        /// algorithm, in this example we will default to AES.
        /// </summary>
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

        /// <inheritdoc/>
        public override ICryptoTransform CreateEncryptor(Stream destinationStream)
        {
            using var newKey = Aes.Create();
            newKey.Key = _key.Key;
            newKey.Mode = _key.Mode;
            newKey.IV = EncryptionUtils.GenerateRandomByteArray(newKey.IV.Length);
            destinationStream.Write(newKey.IV, 0, newKey.IV.Length);
            return newKey.CreateEncryptor();
        }

        /// <inheritdoc/>
        public override ICryptoTransform CreateDecryptor(Stream encryptedStream)
        {
            using var newKey = Aes.Create();
            newKey.Key = _key.Key;
            newKey.Mode = _key.Mode;
            var newIV = new byte[newKey.IV.Length];
            encryptedStream.Read(newIV, 0, newIV.Length);
            newKey.IV = newIV;
            return newKey.CreateDecryptor();
        }

        public override byte[] Serialize()
        {
            return _key.Serialize();
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
            return obj is AesEncryptionKey otherKey
                && otherKey._key.Key.SequenceEqual(_key.Key)
                && otherKey._key.IV.SequenceEqual(_key.IV)
                && otherKey._key.Mode == _key.Mode;
        }

        public override int GetHashCode()
        {
            return _key.GetHashCode();
        }
    }
}
