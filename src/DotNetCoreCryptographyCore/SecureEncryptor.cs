using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// <para>
    /// A class capable to encrypt stream in a secure way using a
    /// <see cref="IKeyVaultStore"/> to protect key used to encrypt.
    /// </para>
    /// <para>
    /// It will use by default a new <see cref="AesEncryptionKey"/> each
    /// time to guarantee maximum security.
    /// </para>
    /// </summary>
    public class SecureEncryptor
    {
        private readonly IKeyVaultStore _keyVaultStore;

        public SecureEncryptor(IKeyVaultStore keyVaultStore)
        {
            _keyVaultStore = keyVaultStore;
        }

        public async Task Encrypt(Stream streamToEncrypt, MemoryStream destinationStream)
        {
            //to encrypt we need to generate a new key
            using var key = EncryptionKey.CreateDefault();

            //now we want to be able to store it securely
            var encrypted = await _keyVaultStore.EncryptAsync(key).ConfigureAwait(false);

            //now we need to generate an output stream that contains both the key and the real 
            //encrypted content, we start writing the size of the encrypted key
            using (var bw = new BinaryWriter(destinationStream))
            {
                bw.Write(encrypted.Length);

                //now write the key encrypted
                bw.Write(encrypted);
                bw.Flush();

                //now use the key to encrypt the rest
                using var encryptor = key.CreateEncryptor(destinationStream);
                using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
                await streamToEncrypt.CopyToAsync(csEncrypt).ConfigureAwait(false);
            }
        }

        public async Task Decrypt(MemoryStream sourceEncryptedStream, MemoryStream destinationDecryptedStream)
        {
            using (var bw = new BinaryReader(sourceEncryptedStream))
            {
                //read the length of the key, then with that value we can read the encrypted key.
                var length = bw.ReadInt32();
                var encryptedKey = bw.ReadBytes(length);
                using var originalKey = await _keyVaultStore.DecriptAsync(encryptedKey).ConfigureAwait(false);
                using var decryptor = originalKey.CreateDecryptor(sourceEncryptedStream);
                using CryptoStream csDecrypt = new(sourceEncryptedStream, decryptor, CryptoStreamMode.Read);
                await csDecrypt.CopyToAsync(destinationDecryptedStream).ConfigureAwait(false);
            }
        }
    }
}
