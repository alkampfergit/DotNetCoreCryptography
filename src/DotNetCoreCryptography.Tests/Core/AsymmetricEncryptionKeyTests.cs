using DotNetCoreCryptographyCore;
using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public abstract class AsymmetricEncryptionKeyTests
    {
        [Fact]
        public void Can_serialize_and_deserialize_key()
        {
            var rsaKey = Create();
            var serialized = rsaKey.Serialize();
            var deserialized = (RsaEncryptionKey) AsymmetricEncryptionKey.CreateFromSerializedVersion(serialized);
            Assert.True(rsaKey.IsEqualTo(deserialized));
        }

        [Fact]
        public void Export_only_public_key()
        {
            var rsaKey = Create();
            var serialized = rsaKey.SerializePublicKey();
            var deserialized = (RsaEncryptionKey)AsymmetricEncryptionKey.CreateFromSerializedVersion(serialized);
            Assert.False(rsaKey.IsEqualTo(deserialized));
            Assert.False(deserialized.HasPrivateKey);
        }

        [Fact]
        public void Can_distinguish_between_public_and_private()
        {
            var rsaKey = Create();
            Assert.True(rsaKey.HasPrivateKey);
        }

        [Fact]
        public void Can_direct_encrypt_data()
        {
            var rsaKey = Create();
            var data = Encoding.UTF8.GetBytes("this is a nice string");
            var encrypted = rsaKey.Encrypt(data);
            var decrypted = rsaKey.Decrypt(encrypted);
            Assert.Equal(data, decrypted);
        }

        [Fact]
        public void Can_direct_encrypt_data_with_only_public_key()
        {
            var rsaKey = Create();
            var publicSerialized = rsaKey.SerializePublicKey();
            var publicKey = AsymmetricEncryptionKey.CreateFromSerializedVersion(publicSerialized);
            Assert.False(publicKey.HasPrivateKey);

            var data = Encoding.UTF8.GetBytes("this is a nice string");
            var encrypted = publicKey.Encrypt(data);
            var decrypted = rsaKey.Decrypt(encrypted);
            Assert.Equal(data, decrypted);
        }

        [Fact]
        public void Cannot_decrypt_with_public_key()
        {
            var rsaKey = Create();
            var publicSerialized = rsaKey.SerializePublicKey();
            var publicKey = AsymmetricEncryptionKey.CreateFromSerializedVersion(publicSerialized);
            Assert.False(publicKey.HasPrivateKey);

            var data = Encoding.UTF8.GetBytes("this is a nice string");
            var encrypted = publicKey.Encrypt(data);
            try
            {
                publicKey.Decrypt(encrypted);
                throw new Exception("Should throw");
            }
            catch (Exception ex)
            {
                Assert.True(ex is CryptographicException);
            }
        }

        /// <summary>
        /// Create the real encryption
        /// </summary>
        /// <returns></returns>
        protected abstract AsymmetricEncryptionKey Create();
    }

    public class RsaEncryptionKeyTests : AsymmetricEncryptionKeyTests
    {
        protected override AsymmetricEncryptionKey Create()
        {
            return new RsaEncryptionKey();
        }
    }
}
