using DotNetCoreCryptographyCore;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class AsymmetricEncryptionKeyTests
    {
        [Fact]
        public void Can_serialize_and_deserialize_key()
        {
            var rsaKey = new RsaEncryptionKey();
            var serialized = rsaKey.Serialize();
            var deserialized = (RsaEncryptionKey) AsymmetricEncryptionKey.CreateFromSerializedVersion(serialized);
            Assert.True(rsaKey.IsEqualTo(deserialized));
        }

        [Fact]
        public void Export_only_public_key()
        {
            var rsaKey = new RsaEncryptionKey();
            var serialized = rsaKey.SerializePublicKey();
            var deserialized = (RsaEncryptionKey)AsymmetricEncryptionKey.CreateFromSerializedVersion(serialized);
            Assert.False(rsaKey.IsEqualTo(deserialized));
            Assert.False(deserialized.HasPrivateKey);
        }

        [Fact]
        public void Can_distinguish_between_public_and_private()
        {
            var rsaKey = new RsaEncryptionKey();
            Assert.True(rsaKey.HasPrivateKey);
        }
    }
}
