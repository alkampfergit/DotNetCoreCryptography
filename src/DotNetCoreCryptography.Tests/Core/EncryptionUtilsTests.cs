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
