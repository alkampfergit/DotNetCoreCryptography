using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    public static class Encryptor
    {
        public static async Task EncryptAsync(Stream sourceStream, Stream destinationStream, Aes aes)
        {
            using var encryptor = aes.CreateEncryptor();
            using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
            await sourceStream.CopyToAsync(csEncrypt).ConfigureAwait(false);
        }

        public static async Task EncryptAsync(Stream sourceStream, Stream destinationStream, EncryptionKey key)
        {
            using var encryptor = key.CreateEncryptor();
            using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
            await sourceStream.CopyToAsync(csEncrypt).ConfigureAwait(false);
        }

        public static async Task DecryptAsync(Stream encryptedStream, Stream destinationStream, Aes aes)
        {
            using var decryptor = aes.CreateDecryptor();
            using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read);
            await csDecrypt.CopyToAsync(destinationStream).ConfigureAwait(false);
        }

        public static async Task DecryptAsync(Stream encryptedStream, Stream destinationStream, EncryptionKey key)
        {
            using var decryptor = key.CreateDecryptor();
            using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read);
            await csDecrypt.CopyToAsync(destinationStream).ConfigureAwait(false);
        }
    }
}
