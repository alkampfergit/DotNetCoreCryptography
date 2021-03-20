using System;
using System.Collections.Generic;
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

        public ICryptoTransform CreateEncryptor()
        {
            return _key.CreateEncryptor();
        }

        public ICryptoTransform CreateDecryptor()
        {
            return _key.CreateDecryptor();
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

        public static bool operator ==(EncryptionKey left, EncryptionKey right)
        {
            return EqualityComparer<EncryptionKey>.Default.Equals(left, right);
        }

        public static bool operator !=(EncryptionKey left, EncryptionKey right)
        {
            return !(left == right);
        }
    }
}
