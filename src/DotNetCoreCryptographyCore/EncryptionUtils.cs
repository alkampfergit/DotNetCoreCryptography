using System;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    public static class EncryptionUtils
    {
        public const Int32 saltSize = 8;

        public static byte[] GenerateRandomSalt()
        {
            using var csp = new RNGCryptoServiceProvider();
            byte[] salt = new byte[saltSize];
            csp.GetBytes(salt);
            return salt;
        }

        public static ICryptoTransform GetEncryptorFromPassword(
            this Aes aes,
            string password,
            byte[] salt)
        {
            using var pdb = new PasswordDeriveBytes(password, salt);
            var key = pdb.GetBytes(32);
            var IV = pdb.GetBytes(16);
            return aes.CreateEncryptor(key, IV);
        }

        public static ICryptoTransform GetDecryptorFromPassword(
            this Aes aes,
            string password,
            byte[] salt)
        {
            using var pdb = new PasswordDeriveBytes(password, salt);
            var key = pdb.GetBytes(32);
            var IV = pdb.GetBytes(16);
            return aes.CreateDecryptor(key, IV);
        }

        public static byte[] Serialize(this Aes aes)
        {
            var array = new byte[
                aes.KeySize / 8     //Key size
                + 16                //IV size
                + 1                 //mode of operation
            ];
            Array.Copy(aes.IV, array, aes.IV.Length);
            Array.Copy(aes.Key, 0, array, 16, aes.Key.Length);
            array[array.Length - 1] = (byte) aes.Mode;
            return array;
        }

        public static Aes DeserializeToAes(this byte[] serializedAes)
        {
            var aes = Aes.Create();
            var keyLength = serializedAes.Length - 16 - 1;
            aes.IV = new ArraySegment<byte>(serializedAes, 0, 16).ToArray();
            aes.Key = new ArraySegment<byte>(serializedAes, 16, keyLength).ToArray();
            aes.Mode = (CipherMode)serializedAes[serializedAes.Length - 1];
            return aes;
        }
    }
}
