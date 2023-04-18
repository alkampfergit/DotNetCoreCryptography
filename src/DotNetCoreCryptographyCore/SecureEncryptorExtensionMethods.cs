using DotNetCoreCryptographyCore.Utils;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    public static class SecureEncryptorExtensionMethods
    {
        public static async Task<string> EncryptAsync(this SecureEncryptor secureEncryptor, string stringToEncrypt)
        {
            using var ms = new MemoryStream(Encoding.UTF8.GetBytes(stringToEncrypt));
            using var outputStream = new MemoryStream(stringToEncrypt.Length);

            await secureEncryptor.Encrypt(ms, outputStream);
            return BitConverter.ToString(outputStream.ToArray()).Replace("-", "");
        }

        public static async Task<string> DecryptAsync(this SecureEncryptor secureEncryptor, string stringToDecrypt)
        {
            var hex = HexEncoding.GetBytes(stringToDecrypt);
            using var ms = new MemoryStream(hex);
            using var outputStream = new MemoryStream(hex.Length);

            await secureEncryptor.Decrypt(ms, outputStream);
            return Encoding.UTF8.GetString(outputStream.ToArray());
        }
    }
}
