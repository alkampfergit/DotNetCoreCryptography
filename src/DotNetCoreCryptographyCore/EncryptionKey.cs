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
    public class EncryptionKey : IDisposable
    {
        /// <summary>
        /// Create a new <see cref="EncryptionKey"/> with the standard configured
        /// algorithm, in this example we will default to AES.
        /// </summary>
        public EncryptionKey()
        {
            _key = Aes.Create();
        }

        public EncryptionKey(byte[] serializedValue)
        {
            _key = serializedValue.DeserializeToAes();
        }

        private readonly Aes _key;
        private bool _disposedValue;

        /// <summary>
        /// Create an encryption envelope, it will return optionally an array of byte to bew
        /// included at the beginning of the stream, in AES is the IV value.
        /// </summary>
        /// <returns></returns>
        public ICryptoTransform CreateEncryptor(Stream destinationStream)
        {
            using var newKey = Aes.Create();
            newKey.Key = _key.Key;
            newKey.Mode = _key.Mode;
            newKey.IV = EncryptionUtils.GenerateRandomByteArray(newKey.IV.Length);
            destinationStream.Write(newKey.IV, 0, newKey.IV.Length);
            return newKey.CreateEncryptor();
        }

        public ICryptoTransform CreateDecryptor(Stream encryptedStream)
        {
            using var newKey = Aes.Create();
            newKey.Key = _key.Key;
            newKey.Mode = _key.Mode;
            var newIV = new byte[newKey.IV.Length];
            encryptedStream.Read(newIV, 0, newIV.Length);
            newKey.IV = newIV;
            return newKey.CreateDecryptor();
        }

        public byte[] Serialize()
        {
            return _key.Serialize();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    _key.Dispose();
                }

                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        public override bool Equals(object obj)
        {
            return obj is EncryptionKey otherKey
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
