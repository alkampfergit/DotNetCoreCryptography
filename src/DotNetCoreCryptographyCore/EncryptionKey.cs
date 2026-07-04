using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Abstract class that implements a key that is able to encrypt a stream with
    /// a symmetric algorithm. The default key type is AES-256-GCM
    /// (<see cref="AesGcmEncryptionKey"/>), which authenticates the ciphertext;
    /// the legacy AES-256-CBC key (<see cref="AesEncryptionKey"/>) is retained
    /// only to decrypt data written by previous versions of the library.
    /// </summary>
    public abstract class EncryptionKey : IDisposable
    {
        public static EncryptionKey CreateDefault()
        {
            return new AesGcmEncryptionKey();
        }

        /// <summary>
        /// Create correct type of key based on serialized version.
        /// </summary>
        /// <param name="serializedKey"></param>
        /// <returns></returns>
        public static EncryptionKey CreateFromSerializedVersion(byte[] serializedKey)
        {
            ArgumentNullException.ThrowIfNull(serializedKey);
            if (serializedKey.Length == 0)
            {
                throw new CryptographicException("Serialized key is empty");
            }
            var keyType = (KeyType)serializedKey[0];
            switch (keyType)
            {
                case KeyType.Aes256:
                    return new AesEncryptionKey(serializedKey);
                case KeyType.Aes256Gcm:
                    return new AesGcmEncryptionKey(serializedKey);
                default:
                    throw new NotSupportedException($"Type of key {keyType} is not supported");
            }
        }

        /// <summary>
        /// Encrypts <paramref name="sourceStream"/> into <paramref name="destinationStream"/>
        /// using this key's format. Key-related material (nonce, per-chunk tags, ...)
        /// is written to the destination stream together with the ciphertext.
        /// </summary>
        /// <param name="sourceStream">Plaintext stream to encrypt.</param>
        /// <param name="destinationStream">Destination stream; it is left open.</param>
        /// <param name="associatedData">Optional data that is authenticated together
        /// with the ciphertext but not encrypted (AEAD keys only). The same value
        /// must be supplied on decryption.</param>
        public abstract void Encrypt(Stream sourceStream, Stream destinationStream, byte[] associatedData = null);

        /// <summary>
        /// Decrypts a stream produced by <see cref="Encrypt(Stream, Stream, byte[])"/>
        /// with the very same key. Throws <see cref="CryptographicException"/> if the
        /// ciphertext (or the associated data) has been modified in any way.
        /// </summary>
        public abstract void Decrypt(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null);

        /// <inheritdoc cref="Encrypt(Stream, Stream, byte[])"/>
        public abstract Task EncryptAsync(Stream sourceStream, Stream destinationStream, byte[] associatedData = null);

        /// <inheritdoc cref="Decrypt(Stream, Stream, byte[])"/>
        public abstract Task DecryptAsync(Stream encryptedStream, Stream destinationStream, byte[] associatedData = null);

        /// <summary>
        /// Create the decryptor for an encrypted stream, a reference to the stream
        /// is needed to retrieve, optionally, first bytes that can contain some
        /// encryption related data store by <see cref="CreateEncryptor(Stream)"/>
        /// method.
        /// </summary>
        /// <param name="encryptedStream">Encrypted stream, it must be encrypted
        /// with the very same type of key used for decryption.</param>
        /// <returns></returns>
        [Obsolete("The transform-based API supports only the legacy unauthenticated AES-CBC format. Use Decrypt/DecryptAsync, which authenticate the ciphertext.")]
        public virtual ICryptoTransform CreateDecryptor(Stream encryptedStream)
        {
            throw new NotSupportedException("This key does not support the legacy transform-based API.");
        }

        /// <summary>
        /// Create an the encryptor to encrypt the stream, a reference to the
        /// destination stream is used because the key can, optionally, use the
        /// first bytes of the stream to store key related material. In Aes the
        /// encryptionKey will save IV at the beginning of the stream.
        /// </summary>
        /// <param name="destinationStream">destination stream to encrypt, this stream
        /// should be empty so the method can store encryption related information</param>
        /// <returns></returns>
        [Obsolete("The transform-based API supports only the legacy unauthenticated AES-CBC format. Use Encrypt/EncryptAsync, which authenticate the ciphertext.")]
        public virtual ICryptoTransform CreateEncryptor(Stream destinationStream)
        {
            throw new NotSupportedException("This key does not support the legacy transform-based API.");
        }

        /// <summary>
        /// The key should be able to be serialized in a simple byte array to be stored
        /// in some destination.
        /// </summary>
        /// <returns></returns>
        public abstract byte[] Serialize();

        /// <summary>
        /// Returns a copy of the raw symmetric key bytes, used to load the key into
        /// an <see cref="Aes"/> instance for RFC 5649 key wrapping. Callers must
        /// zero the returned buffer after use.
        /// </summary>
        internal virtual byte[] ExportRawKeyMaterial()
        {
            throw new NotSupportedException($"{GetType().Name} cannot export raw key material.");
        }

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
