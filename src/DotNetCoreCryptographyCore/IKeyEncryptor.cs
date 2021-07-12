using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// A generic interface that is capable to secure encrypt/decrypt a key
    /// to protect the usage. In Azure or other cloud it is supposed to 
    /// be implemented by a class that uses standard KeyVault of the provider,
    /// if possible implemented with HSM.
    /// </summary>
    public interface IKeyEncryptor
    {
        /// <summary>
        /// Encrypt requested key and return encrypted value as byte array, caller does
        /// not know nor the key nor the method used to encrypt the key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public Task<byte[]> EncryptAsync(EncryptionKey key);

        /// <summary>
        /// You need to call this method with a result of the <see cref="EncryptAsync(EncryptionKey)"/>
        /// method of the same concrete class.
        /// </summary>
        /// <param name="encryptedKey"></param>
        /// <returns></returns>
        public Task<EncryptionKey> DecryptAsync(byte[] encryptedKey);
    }
}
