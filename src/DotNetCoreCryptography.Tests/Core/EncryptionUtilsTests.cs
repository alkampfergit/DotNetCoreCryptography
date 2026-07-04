using DotNetCoreCryptographyCore;
using System.Security.Cryptography;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class EncryptionUtilsTests
    {
        [Fact]
        public void CanSerializeAndDeserializeKey()
        {
            using var aes = Aes.Create();
            var serialied = aes.Serialize();
            using var aesDeserialized = serialied.DeserializeToAes();
            Assert.Equal(aes.Key, aesDeserialized.Key);
            Assert.Equal(aes.IV, aesDeserialized.IV);
        }

        [Fact]
        public void Verify_that_serialization_has_byte_mark()
        {
            using var aes = Aes.Create();
            Assert.Equal(256 / 8, aes.Key.Length);
            var serialized = aes.Serialize();
            Assert.Equal((byte) KeyType.Aes256, serialized[0]);
        }

        [Fact]
        public void Verify_deserialize_check_byte_mark()
        {
            using var aes = Aes.Create();
            Assert.Equal(256 / 8, aes.Key.Length);
            var serialized = aes.Serialize();

            //Alter type of serialized key, it should throw
            serialized[0] = 0;
            Assert.Throws<CryptographicException>(() => serialized.DeserializeToAes());
        }

        [Fact]
        public void SerializationMaintainsCbcMode()
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            var serialized = aes.Serialize();
            using var aesDeserialized = serialized.DeserializeToAes();
            Assert.Equal(CipherMode.CBC, aesDeserialized.Mode);
        }

        [Theory]
        [InlineData(CipherMode.ECB)]
        [InlineData(CipherMode.CFB)]
        public void Serialization_rejects_non_cbc_modes(CipherMode mode)
        {
            //only CBC was ever written by the library; accepting other modes would
            //allow an algorithm downgrade through a tampered key blob (SEC-5)
            using var aes = Aes.Create();
            aes.Mode = mode;
            Assert.Throws<CryptographicException>(() => aes.Serialize());
        }

        [Fact]
        public void Deserialization_rejects_tampered_mode_byte()
        {
            using var aes = Aes.Create();
            var serialized = aes.Serialize();
            serialized[^1] = (byte)CipherMode.ECB;
            Assert.Throws<CryptographicException>(() => serialized.DeserializeToAes());
        }

        [Fact]
        public void Deserialization_rejects_truncated_key()
        {
            using var aes = Aes.Create();
            var serialized = aes.Serialize();
            Assert.Throws<CryptographicException>(() => serialized[..^16].DeserializeToAes());
        }
    }
}
