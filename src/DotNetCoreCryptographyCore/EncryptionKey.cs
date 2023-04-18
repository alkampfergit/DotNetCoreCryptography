using System;
using System.IO;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Abstract class that implemnt a key that is 
    /// able to encrypt a stream. Usually this is a
    /// symmetric algorithm, in this first version we
    /// only have AES.
    /// </summary>
    public abstract class EncryptionKey : IDisposable
    {
        public static EncryptionKey CreateDefault()
        {
            return new AesEncryptionKey();
        }

        /// <summary>
        /// Create correct type of key based on serialied version.
        /// </summary>
        /// <param name="serializedKey"></param>
        /// <returns></returns>
        public static EncryptionKey CreateFromSerializedVersion(byte[] serializedKey)
        {
            var keyType = (KeyType)serializedKey[0];
            switch (keyType)
            {
                case KeyType.Aes256:
                    return new AesEncryptionKey(serializedKey);
                default:
                    throw new NotSupportedException($"Type of key {keyType} is not supported");
            }
        }

        /// <summary>
        /// Create the decryptor for an encrypted stream, a reference to the stream
        /// is needed to retrieve, optionally, first bytes that can contain some
        /// encryption related data store by <see cref="CreateEncryptor(Stream)"/>
        /// method.
        /// </summary>
        /// <param name="encryptedStream">Encrypted stream, it must be encrypted
        /// with the very same type of key used for decryption.</param>
        /// <returns></returns>
        public abstract ICryptoTransform CreateDecryptor(Stream encryptedStream);

        /// <summary>
        /// Create an the encryptor to encrypt the stream, a reference to the 
        /// destination stream is used because the key can, optionally, use the
        /// first bytes of the stream to store key related material. In Aes the 
        /// encryptionKey will save IV at the beginning of the stream.
        /// </summary>
        /// <param name="destinationStream">destination stream to encrypt, this stream
        /// should be empty so the method can store encryption related information</param>
        /// <returns></returns>
        public abstract ICryptoTransform CreateEncryptor(Stream destinationStream);

        /// <summary>
        /// The key should be able to be serialized in a simple byte array to be stored
        /// in some destination.
        /// </summary>
        /// <returns></returns>
        public abstract byte[] Serialize();

        protected bool IsDisposed { get; private set; }

        protected virtual void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                OnDispose(disposing);
                IsDisposed = true;
            }
        }

        protected virtual void OnDispose(bool disposing) { }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}