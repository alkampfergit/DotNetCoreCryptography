using System;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// All asymmetric algorithm use a key that contains
    /// a private and a public part, this class is the base
    /// class that contains an asymmetric key.
    /// </summary>
    public abstract class AsymmetricEncryptionKey : IDisposable
    {
        public static AsymmetricEncryptionKey CreateFromSerializedVersion(byte[] serializedKey)
        {
            var keyType = (AsymmetricKeyType)serializedKey[0];
            switch (keyType)
            {
                case AsymmetricKeyType.Rsa4096: 
                    return new RsaEncryptionKey(serializedKey);
                default:
                    throw new NotSupportedException($"Type of key {keyType} is not supported");
            }
        }

        /// <summary>
        /// The key should be able to be serialized in a simple byte array to be stored
        /// in some secure storage, remember that this method will return a serialized
        /// version that contains both public and private part of the key, so it must
        /// be kept secure.
        /// </summary>
        /// <returns></returns>
        public abstract byte[] Serialize();

        public abstract byte[] Encrypt(byte[] data);

        public abstract byte[] Decrypt(byte[] encryptedData);

        /// <summary>
        /// Serialize only public part of the key, this can be used to recreate a
        /// simple RSA object that contains only public part of the key.
        /// </summary>
        /// <returns></returns>
        public abstract byte[] SerializePublicKey();

        protected bool IsDisposed { get; private set; }

        /// <summary>
        /// Custom IsEqualTo function to compare two key, each concrete 
        /// key should implement its own check function.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public abstract bool IsEqualTo(AsymmetricEncryptionKey other);

        public bool HasPrivateKey { get; protected set; }

        protected virtual void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                OnDispose(disposing);
                IsDisposed = true;
            }
        }

        protected abstract void OnDispose(bool disposing);

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
