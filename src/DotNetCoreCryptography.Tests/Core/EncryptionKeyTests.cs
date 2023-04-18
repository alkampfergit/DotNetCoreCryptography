using DotNetCoreCryptographyCore;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class EncryptionKeyTests
    {
        [Fact]
        public void Can_serialize_and_deserialize_key()
        {
            var aesKey = new AesEncryptionKey();
            var serialized = aesKey.Serialize();
            var deserialized = EncryptionKey.CreateFromSerializedVersion(serialized);
            Assert.Equal(aesKey, deserialized);
        }

        [Fact]
        public void Each_call_generate_different_key() 
        {
            Assert.NotEqual(EncryptionKey.CreateDefault(), EncryptionKey.CreateDefault());
        }
    }
}
