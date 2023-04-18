using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    public static class StaticEncryptor
    {
        public static async Task EncryptAsync(Stream sourceStream, Stream destinationStream, EncryptionKey key)
        {
            using var encryptor = key.CreateEncryptor(destinationStream);
            using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
            await sourceStream.CopyToAsync(csEncrypt).ConfigureAwait(false);
        }

        public static void Encrypt(Stream sourceStream, Stream destinationStream, EncryptionKey key)
        {
            using var encryptor = key.CreateEncryptor(destinationStream);
            using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
            sourceStream.CopyTo(csEncrypt);
        }

        public static async Task<String> EncryptAsync(string content, EncryptionKey key)
        {
            var data = Encoding.UTF8.GetBytes(content);
            using var sourceStream = new MemoryStream(data);
            using var destMs = new MemoryStream(data.Length);
            await EncryptAsync(sourceStream, destMs, key).ConfigureAwait(false);

            return Convert.ToBase64String(destMs.ToArray());
        }

        public static String Encrypt(string content, EncryptionKey key)
        {
            var data = Encoding.UTF8.GetBytes(content);
            using var sourceStream = new MemoryStream(data);
            using var destMs = new MemoryStream(data.Length);
            Encrypt(sourceStream, destMs, key);

            return Convert.ToBase64String(destMs.ToArray());
        }

        public static async Task DecryptAsync(Stream encryptedStream, Stream destinationStream, EncryptionKey key)
        {
            using var decryptor = key.CreateDecryptor(encryptedStream);
            using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read);
            await csDecrypt.CopyToAsync(destinationStream).ConfigureAwait(false);
        }

        public static void Decrypt(Stream encryptedStream, Stream destinationStream, EncryptionKey key)
        {
            using var decryptor = key.CreateDecryptor(encryptedStream);
            using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read);
            csDecrypt.CopyTo(destinationStream);
        }

        public static async Task<string> DecryptAsync(string encryptedBase64String, EncryptionKey key)
        {
            var data = Convert.FromBase64String(encryptedBase64String);
            using var ms = new MemoryStream(data);
            using var destMs = new MemoryStream();
            await DecryptAsync(ms, destMs, key).ConfigureAwait(false);
            return Encoding.UTF8.GetString(destMs.ToArray());
        }

        public static string Decrypt(string encryptedBase64String, EncryptionKey key)
        {
            var data = Convert.FromBase64String(encryptedBase64String);
            using var ms = new MemoryStream(data);
            using var destMs = new MemoryStream();
            Decrypt(ms, destMs, key);
            return Encoding.UTF8.GetString(destMs.ToArray());
        }

        public static async Task AesEncryptWithPasswordAsync(Stream sourceStream, Stream destinationStream, string password)
        {
            using var rng = RandomNumberGenerator.Create();
            var salt = new byte[16];
            rng.GetBytes(salt);
            var aes = Aes.Create();
            using var encryptor = aes.GetEncryptorFromPassword(password, salt);
            //need to write salt unencrypted in final stream
            destinationStream.Write(salt, 0, salt.Length);
            using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
            await sourceStream.CopyToAsync(csEncrypt).ConfigureAwait(false);
        }

        public static void AesEncryptWithPassword(
            Stream sourceStream,
            Stream destinationStream,
            string password)
        {
            using var rng = RandomNumberGenerator.Create();
            var salt = new byte[16];
            rng.GetBytes(salt);
            var aes = Aes.Create();
            using var encryptor = aes.GetEncryptorFromPassword(password, salt);
            //need to write salt unencrypted in final stream
            destinationStream.Write(salt, 0, salt.Length);
            using CryptoStream csEncrypt = new(destinationStream, encryptor, CryptoStreamMode.Write);
            sourceStream.CopyTo(csEncrypt);
            sourceStream.Flush();
        }

        public static async Task<byte[]> AesEncryptWithPasswordAsync(byte[] data, string password)
        {
            using var sourceStream = new MemoryStream(data);
            using var destinationStream = new MemoryStream(data.Length);
            await AesEncryptWithPasswordAsync(sourceStream, destinationStream, password).ConfigureAwait(false);
            return destinationStream.ToArray();
        }

        public static byte[] AesEncryptWithPassword(byte[] data, string password)
        {
            using var sourceStream = new MemoryStream(data);
            using var destinationStream = new MemoryStream(data.Length);
            AesEncryptWithPassword(sourceStream, destinationStream, password);
            return destinationStream.ToArray();
        }

        public static async Task AesDecryptWithPasswordAsync(Stream encryptedStream, Stream destinationStream, string password)
        {
            var salt = new byte[16];
            encryptedStream.Read(salt, 0, salt.Length);
            var aes = Aes.Create();
            using var decryptor = aes.GetDecryptorFromPassword(password, salt);
            using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read);
            await csDecrypt.CopyToAsync(destinationStream).ConfigureAwait(false);
            await csDecrypt.FlushAsync();
        }

        public static void AesDecryptWithPassword(Stream encryptedStream, Stream destinationStream, string password)
        {
            var salt = new byte[16];
            encryptedStream.Read(salt, 0, salt.Length);
            var aes = Aes.Create();
            using var decryptor = aes.GetDecryptorFromPassword(password, salt);
            using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read);
            csDecrypt.CopyTo(destinationStream);
            csDecrypt.Flush();
        }

        public static async Task<byte[]> AesDecryptWithPasswordAsync(byte[] encryptedData, string password)
        {
            using var sourceStream = new MemoryStream(encryptedData);
            using var destinationStream = new MemoryStream(encryptedData.Length);
            await AesDecryptWithPasswordAsync(sourceStream, destinationStream, password).ConfigureAwait(false);
            return destinationStream.ToArray();
        }

        public static byte[] AesDecryptWithPassword(byte[] encryptedData, string password)
        {
            using var sourceStream = new MemoryStream(encryptedData);
            using var destinationStream = new MemoryStream(encryptedData.Length);
            AesDecryptWithPassword(sourceStream, destinationStream, password);
            return destinationStream.ToArray();
        }
    }
}
