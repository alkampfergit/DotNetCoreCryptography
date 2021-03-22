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
            Assert.Equal(aes.Key.Length, 256 / 8);
            var serialized = aes.Serialize();
            Assert.Equal((byte) KeyType.Aes256, serialized[0]);
        }

        [Fact]
        public void Verify_deserialize_check_byte_mark()
        {
            using var aes = Aes.Create();
            Assert.Equal(aes.Key.Length, 256 / 8);
            var serialized = aes.Serialize();

            //Alter type of serialized key, it should throw
            serialized[0] = 0;
            Assert.Throws<CryptographicException>(() => serialized.DeserializeToAes());
        }

        [Theory]
        [InlineData(CipherMode.CBC)]
        [InlineData(CipherMode.ECB)]
        [InlineData(CipherMode.CFB)]
        public void SerializationMaintainModeOfOperation(CipherMode mode)
        {
            using var aes = Aes.Create();
            aes.Mode = mode;
            var serialied = aes.Serialize();
            using var aesDeserialized = serialied.DeserializeToAes();
            Assert.Equal(aes.Mode, aesDeserialized.Mode);
        }
    }
}
