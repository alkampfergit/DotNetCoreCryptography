using DotNetCoreCryptographyCore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class AsymmetricSecureEncryptorTests
    {
        [Fact]
        public async Task Full_secure_asymmetric_encryption_test()
        {
            using var streamToEncrypt = GenerateStreamToEncrypt();

            //ok now we need to secure encrypt and decrypt the stream
            using var destinationStream = new MemoryStream();
            var key = new RsaEncryptionKey();
            var publicKey = AsymmetricEncryptionKey.CreateFromSerializedVersion(key.SerializePublicKey());
            await AsymmetricSecureEncryptor.Encrypt(publicKey, streamToEncrypt, destinationStream);

            //now we want to read again and decrypt
            using var sourceEncryptedStream = new MemoryStream(destinationStream.ToArray());
            using var destinationDecryptedStream = new MemoryStream();
            await AsymmetricSecureEncryptor.Decrypt(key, sourceEncryptedStream, destinationDecryptedStream);
            var decryptedContent = Encoding.UTF8.GetString(destinationDecryptedStream.ToArray());
            Assert.Equal(decryptedContent, someContenttoBeEncrypted);
        }

        const string someContenttoBeEncrypted = "this test will be encrypted with asymmetric key";

        private Stream GenerateStreamToEncrypt()
        {
            byte[] stringContent = Encoding.UTF8.GetBytes(someContenttoBeEncrypted);
            return new MemoryStream(stringContent);
        }
    }
}
