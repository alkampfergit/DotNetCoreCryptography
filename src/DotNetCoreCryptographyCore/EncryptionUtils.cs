using System;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    public static class EncryptionUtils
    {
        public static byte[] GenerateRandomByteArray(int size)
        {
            return RandomNumberGenerator.GetBytes(size);
        }

        // WARNING: PBKDF2-HMAC-SHA1 at 1000 iterations is retained here only for
        // backward compatibility with data already encrypted by this library (the
        // legacy v1 password format). New data is written in the v2 format by
        // StaticEncryptor with PBKDF2-HMAC-SHA256 at 600,000 iterations.
        private const int LegacyPbkdf2Iterations = 1000;

        [Obsolete("This produces the legacy unauthenticated v1 password format with a weak KDF. Use StaticEncryptor.AesEncryptWithPassword, which writes the authenticated v2 format.")]
        public static ICryptoTransform GetEncryptorFromPassword(
            this Aes aes,
            string password,
            byte[] salt)
        {
            var (key, iv) = DeriveKeyAndIv(password, salt);
            return aes.CreateEncryptor(key, iv);
        }

        /// <summary>
        /// Legacy (v1) password-based decryptor, kept to read data written before
        /// the authenticated v2 format was introduced.
        /// </summary>
        public static ICryptoTransform GetDecryptorFromPassword(
            this Aes aes,
            string password,
            byte[] salt)
        {
            var (key, iv) = DeriveKeyAndIv(password, salt);
            return aes.CreateDecryptor(key, iv);
        }

        private static (byte[] Key, byte[] Iv) DeriveKeyAndIv(string password, byte[] salt)
        {
            // Derive key (32 bytes) followed by IV (16 bytes) from a single PBKDF2
            // stream, matching the previous sequential GetBytes(32)/GetBytes(16) layout
            // so existing ciphertext remains decryptable.
            var derived = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                LegacyPbkdf2Iterations,
                HashAlgorithmName.SHA1,
                48);
            return (derived[..32], derived[32..]);
        }

        private const int SerializedAesLength =
            1                   // first byte mark
            + 16                // IV size
            + 32                // key size (256 bit)
            + 1;                // mode of operation

        /// <summary>
        /// Serialize an AES key into a byte array. Only AES-256 in CBC mode is
        /// accepted: this is the legacy (v1) key layout and no other combination
        /// was ever written by this library.
        /// </summary>
        /// <param name="aes"></param>
        /// <returns></returns>
        public static byte[] Serialize(this Aes aes)
        {
            if (aes.KeySize != 256)
            {
                throw new CryptographicException($"Only 256 bit AES keys can be serialized, key is {aes.KeySize} bit");
            }
            if (aes.Mode != CipherMode.CBC)
            {
                throw new CryptographicException($"Only CipherMode.CBC legacy keys can be serialized, mode is {aes.Mode}");
            }
            var array = new byte[SerializedAesLength];
            array[0] = (byte)KeyType.Aes256;
            Array.Copy(aes.IV, 0, array, 1, aes.IV.Length);
            Array.Copy(aes.Key, 0, array, 16 + 1, aes.Key.Length);
            array[^1] = (byte)aes.Mode;
            return array;
        }

        public static Aes DeserializeToAes(this byte[] serializedAes)
        {
            ArgumentNullException.ThrowIfNull(serializedAes);
            if (serializedAes.Length == 0 || serializedAes[0] != (byte)KeyType.Aes256)
            {
                throw new CryptographicException("Serialized key is not AES");
            }
            if (serializedAes.Length != SerializedAesLength)
            {
                throw new CryptographicException("Serialized AES key has an invalid length");
            }
            // Reject any mode other than CBC: a tampered mode byte could otherwise
            // downgrade the cipher to ECB (see security finding SEC-5).
            if ((CipherMode)serializedAes[^1] != CipherMode.CBC)
            {
                throw new CryptographicException("Serialized AES key specifies an unsupported cipher mode, only CBC is accepted for legacy keys");
            }
            var aes = Aes.Create();
            aes.IV = new ArraySegment<byte>(serializedAes, 1, 16).ToArray();
            aes.Key = new ArraySegment<byte>(serializedAes, 17, 32).ToArray();
            aes.Mode = CipherMode.CBC;
            return aes;
        }
    }
}
