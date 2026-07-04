using DotNetCoreCryptographyCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Core
{
    public class AsymmetricEncryptionUtilsTests
    {
        [Fact]
        public void Can_compare_RSA_parameters() 
        {
            using var rsa = RSA.Create(4096);
            var p1 = rsa.ExportParameters(true);
            var p2 = rsa.ExportParameters(true);
            Assert.True(p1.KeyEqual(p2));
        }

        [Fact]
        public void CanSerializeAndDeserializeKey()
        {
            using var rsa = RSA.Create(4096);
            var serialied = rsa.Serialize(true);
            using var rsaDeserialized = serialied.DeserializeToRsa(out var _);
            Assert.True(rsa.ExportParameters(true).KeyEqual(rsaDeserialized.ExportParameters(true)));
        }

        [Theory]
        [InlineData(int.MaxValue)]
        [InlineData(int.MinValue)]
        [InlineData(0)]
        public void DeserializeToRsaRejectsInvalidExponentLengthBeforeAllocating(int length)
        {
            var serialized = new byte[1 + 1 + sizeof(int)];
            serialized[0] = (byte)AsymmetricKeyType.Rsa4096;
            serialized[1] = 0;
            BitConverter.GetBytes(length).CopyTo(serialized, 2);

            Assert.Throws<CryptographicException>(() => serialized.DeserializeToRsa(out var _));
        }

        [Fact]
        public void DeserializeToRsaRejectsTruncatedComponent()
        {
            var serialized = new byte[]
            {
                (byte)AsymmetricKeyType.Rsa4096,
                0,
                3, 0, 0, 0,
                1
            };

            Assert.Throws<CryptographicException>(() => serialized.DeserializeToRsa(out var _));
        }
    }
}
