using System;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    public static class EncryptionUtils
    {
        public static byte[] GenerateRandomByteArray(int size)
        {
            using var csp = new RNGCryptoServiceProvider();
            byte[] salt = new byte[size];
            csp.GetBytes(salt);
            return salt;
        }

        public static ICryptoTransform GetEncryptorFromPassword(
            this Aes aes,
            string password,
            byte[] salt)
        {
            using var k1 = new Rfc2898DeriveBytes(password, salt, 1000);
            var key = k1.GetBytes(32);
            var IV = k1.GetBytes(16);
            return aes.CreateEncryptor(key, IV);
        }

        public static ICryptoTransform GetDecryptorFromPassword(
            this Aes aes,
            string password,
            byte[] salt)
        {
            using var k1 = new Rfc2898DeriveBytes(password, salt, 1000);
            var key = k1.GetBytes(32);
            var IV = k1.GetBytes(16);
            return aes.CreateDecryptor(key, IV);
        }

        /// <summary>
        /// Serialize an AES key into a byte array
        /// </summary>
        /// <param name="aes"></param>
        /// <returns></returns>
        public static byte[] Serialize(this Aes aes)
        {
            var array = new byte[
                aes.KeySize / 8     //Key size
                + 16                //IV size
                + 1                 //mode of operation
                + 1                 //first byte mark
            ];
            array[0] = (byte) KeyType.Aes256;
            Array.Copy(aes.IV, 0, array, 1, aes.IV.Length);
            Array.Copy(aes.Key, 0, array, 16 + 1, aes.Key.Length);
            array[^1] = (byte) aes.Mode;
            return array;
        }

        public static Aes DeserializeToAes(this byte[] serializedAes)
        {
            if (serializedAes[0] != (byte) KeyType.Aes256) 
            {
                throw new CryptographicException("Serialized key is not AES");
            }
            var aes = Aes.Create();
            var keyLength = serializedAes.Length - 16 - 1 - 1;
            aes.IV = new ArraySegment<byte>(serializedAes, 1, 16).ToArray();
            aes.Key = new ArraySegment<byte>(serializedAes, 17, keyLength).ToArray();
            aes.Mode = (CipherMode)serializedAes[^1];
            return aes;
        }
    }
}
