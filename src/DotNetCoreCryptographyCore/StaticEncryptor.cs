using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Static helpers to encrypt/decrypt streams, byte arrays and strings with an
    /// <see cref="EncryptionKey"/> or with a password. Since format v2 all data is
    /// written with authenticated encryption (AES-256-GCM); the legacy v1 (AES-CBC)
    /// format is still transparently detected and decrypted.
    /// </summary>
    public static class StaticEncryptor
    {
        private const int PasswordSaltLength = 16;

        // OWASP-recommended work factor for PBKDF2-HMAC-SHA256.
        private const int Pbkdf2Iterations = 600_000;

        public static async Task EncryptAsync(Stream sourceStream, Stream destinationStream, EncryptionKey key)
        {
            await key.EncryptAsync(sourceStream, destinationStream).ConfigureAwait(false);
        }

        public static void Encrypt(Stream sourceStream, Stream destinationStream, EncryptionKey key)
        {
            key.Encrypt(sourceStream, destinationStream);
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
            await key.DecryptAsync(encryptedStream, destinationStream).ConfigureAwait(false);
        }

        public static void Decrypt(Stream encryptedStream, Stream destinationStream, EncryptionKey key)
        {
            key.Decrypt(encryptedStream, destinationStream);
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
            var salt = RandomNumberGenerator.GetBytes(PasswordSaltLength);
            var header = BuildPasswordHeader(salt);
            await destinationStream.WriteAsync(header).ConfigureAwait(false);
            using var key = DerivePasswordKey(password, salt);
            await key.EncryptAsync(sourceStream, destinationStream, associatedData: header).ConfigureAwait(false);
        }

        public static void AesEncryptWithPassword(
            Stream sourceStream,
            Stream destinationStream,
            string password)
        {
            var salt = RandomNumberGenerator.GetBytes(PasswordSaltLength);
            var header = BuildPasswordHeader(salt);
            destinationStream.Write(header, 0, header.Length);
            using var key = DerivePasswordKey(password, salt);
            key.Encrypt(sourceStream, destinationStream, associatedData: header);
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
            var prefix = new byte[CryptoFormat.MagicLength];
            await encryptedStream.ReadExactlyAsync(prefix).ConfigureAwait(false);
            if (CryptoFormat.StartsWithV2Magic(prefix))
            {
                var salt = new byte[PasswordSaltLength];
                await encryptedStream.ReadExactlyAsync(salt).ConfigureAwait(false);
                var header = BuildPasswordHeader(salt);
                using var key = DerivePasswordKey(password, salt);
                await key.DecryptAsync(encryptedStream, destinationStream, associatedData: header).ConfigureAwait(false);
            }
            else
            {
                var salt = await ReadLegacySaltAsync(encryptedStream, prefix).ConfigureAwait(false);
                using var aes = Aes.Create();
                using var decryptor = aes.GetDecryptorFromPassword(password, salt);
                using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
                await csDecrypt.CopyToAsync(destinationStream).ConfigureAwait(false);
            }
        }

        public static void AesDecryptWithPassword(Stream encryptedStream, Stream destinationStream, string password)
        {
            var prefix = new byte[CryptoFormat.MagicLength];
            encryptedStream.ReadExactly(prefix);
            if (CryptoFormat.StartsWithV2Magic(prefix))
            {
                var salt = new byte[PasswordSaltLength];
                encryptedStream.ReadExactly(salt);
                var header = BuildPasswordHeader(salt);
                using var key = DerivePasswordKey(password, salt);
                key.Decrypt(encryptedStream, destinationStream, associatedData: header);
            }
            else
            {
                var salt = new byte[PasswordSaltLength];
                prefix.CopyTo(salt, 0);
                encryptedStream.ReadExactly(salt.AsSpan(CryptoFormat.MagicLength));
                using var aes = Aes.Create();
                using var decryptor = aes.GetDecryptorFromPassword(password, salt);
                using CryptoStream csDecrypt = new(encryptedStream, decryptor, CryptoStreamMode.Read, leaveOpen: true);
                csDecrypt.CopyTo(destinationStream);
            }
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

        /// <summary>
        /// v2 password format: <c>[magic][16-byte salt][AES-GCM chunked payload]</c>.
        /// The header (magic + salt) is bound to the payload as associated data.
        /// KDF parameters are implied by the format version so a tampered header
        /// cannot lower them (and cannot raise them to stage a CPU-exhaustion DoS).
        /// </summary>
        private static byte[] BuildPasswordHeader(byte[] salt)
        {
            var header = new byte[CryptoFormat.MagicLength + PasswordSaltLength];
            CryptoFormat.V2Magic.CopyTo(header, 0);
            salt.CopyTo(header, CryptoFormat.MagicLength);
            return header;
        }

        private static AesGcmEncryptionKey DerivePasswordKey(string password, byte[] salt)
        {
            var keyBytes = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                32);
            try
            {
                //explicit span to select the raw-key-material constructor and not
                //the one that parses a serialized key
                return new AesGcmEncryptionKey(keyBytes.AsSpan());
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyBytes);
            }
        }

        /// <summary>
        /// Legacy v1 password format: the stream starts directly with the 16-byte
        /// random salt (no magic), of which <paramref name="alreadyRead"/> bytes
        /// have already been consumed by format sniffing.
        /// </summary>
        private static async Task<byte[]> ReadLegacySaltAsync(Stream encryptedStream, byte[] alreadyRead)
        {
            var salt = new byte[PasswordSaltLength];
            alreadyRead.CopyTo(salt, 0);
            await encryptedStream.ReadExactlyAsync(salt.AsMemory(alreadyRead.Length)).ConfigureAwait(false);
            return salt;
        }
    }
}
