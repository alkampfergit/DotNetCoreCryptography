using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// <para>
    /// A class capable to encrypt stream in a secure way using a
    /// <see cref="IKeyEncryptor"/> to protect key used to encrypt.
    /// </para>
    /// <para>
    /// It will use by default a new <see cref="EncryptionKey"/> each
    /// time to guarantee maximum security.
    /// </para>
    /// </summary>
    public class SecureEncryptor
    {
        private readonly IKeyEncryptor _keyEncryptor;

        /// <summary>
        /// Secure encryptor needs a key encryptor to safely encrypt and
        /// decrypt keys into stream for secure encryption.
        /// </summary>
        /// <param name="keyEncryptor"></param>
        public SecureEncryptor(IKeyEncryptor keyEncryptor)
        {
            _keyEncryptor = keyEncryptor;
        }

        /// <summary>
        /// Encrypt a stream generating a symmetric key, then encrypt with
        /// a <see cref="IKeyEncryptor"/> and store the encrypted key in destination
        /// stream.
        /// </summary>
        /// <param name="streamToEncrypt"></param>
        /// <param name="destinationStream"></param>
        /// <returns></returns>
        public async Task Encrypt(Stream streamToEncrypt, Stream destinationStream)
        {
            //to encrypt we need to generate a new key
            using var key = EncryptionKey.CreateDefault();

            //now we want to be able to store it securely
            var encrypted = await _keyEncryptor.EncryptAsync(key).ConfigureAwait(false);

            //now we need to generate an output stream that contains both the key and the real 
            //encrypted content, we start writing the size of the encrypted key
            using var bw = new BinaryWriter(destinationStream);
            bw.Write(encrypted.Length);

            //now write the key encrypted
            bw.Write(encrypted);
            bw.Flush();

            //now use the key to encrypt the rest
            using var encryptor = key.CreateEncryptor(destinationStream);
            using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
            await streamToEncrypt.CopyToAsync(csEncrypt).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt a stream encrypted by <see cref="Encrypt(Stream, Stream)"/> method. Encrypted
        /// stream contains an header that contains the key used to encrypt the stream, the
        /// key is encrypted using <see cref="IKeyEncryptor"/>.
        /// </summary>
        /// <param name="sourceEncryptedStream"></param>
        /// <param name="destinationDecryptedStream"></param>
        /// <returns></returns>
        public async Task Decrypt(Stream sourceEncryptedStream, Stream destinationDecryptedStream)
        {
            using var bw = new BinaryReader(sourceEncryptedStream);
            //read the length of the key, then with that value we can read the encrypted key.
            var length = bw.ReadInt32();
            var encryptedKey = bw.ReadBytes(length);
            using var originalKey = await _keyEncryptor.DecryptAsync(encryptedKey).ConfigureAwait(false);
            using var decryptor = originalKey.CreateDecryptor(sourceEncryptedStream);
            using CryptoStream csDecrypt = new(sourceEncryptedStream, decryptor, CryptoStreamMode.Read);
            await csDecrypt.CopyToAsync(destinationDecryptedStream).ConfigureAwait(false);
        }
    }
}
