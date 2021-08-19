using DotNetCoreCryptographyCore;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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

        [Fact]
        public async Task Cannot_decrypt_with_only_public_key()
        {
            using var streamToEncrypt = GenerateStreamToEncrypt();

            //ok now we need to secure encrypt and decrypt the stream
            using var destinationStream = new MemoryStream();
            var key = new RsaEncryptionKey();

            // create a version of the RSA key with only public key part
            var publicKey = AsymmetricEncryptionKey.CreateFromSerializedVersion(key.SerializePublicKey());
            await AsymmetricSecureEncryptor.Encrypt(publicKey, streamToEncrypt, destinationStream).ConfigureAwait(false);

            // we need to be sure that we cannot decrypt the stream if we use only the public part of the key
            using var sourceEncryptedStream = new MemoryStream(destinationStream.ToArray());
            using var destinationDecryptedStream = new MemoryStream();
            await Assert.ThrowsAsync<CryptographicException>(async () => 
                await AsymmetricSecureEncryptor.Decrypt(publicKey, sourceEncryptedStream, destinationDecryptedStream).ConfigureAwait(false)).ConfigureAwait(false);
        }

        const string someContenttoBeEncrypted = "this test will be encrypted with asymmetric key";

        private Stream GenerateStreamToEncrypt()
        {
            byte[] stringContent = Encoding.UTF8.GetBytes(someContenttoBeEncrypted);
            return new MemoryStream(stringContent);
        }
    }
}
