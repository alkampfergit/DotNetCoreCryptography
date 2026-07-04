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

        [Fact]
        public void DeserializeToRsaRejectsDowngradedKeySize()
        {
            //a blob carrying a 2048-bit key but tagged Rsa4096 is a strength downgrade
            //and must be rejected on deserialize (SEC-5)
            using var rsa = RSA.Create(2048);
            var serialized = SerializeAsRsa4096(rsa.ExportParameters(true));

            Assert.Throws<CryptographicException>(() => serialized.DeserializeToRsa(out var _));
        }

        //mirrors AsymmetricEncryptionUtils.Serialize wire format but stamps the
        //Rsa4096 tag regardless of key size, so we can forge a downgraded blob that
        //the production Serialize would refuse to write.
        private static byte[] SerializeAsRsa4096(RSAParameters pp)
        {
            using var ms = new System.IO.MemoryStream();
            using var bw = new System.IO.BinaryWriter(ms);

            bw.Write((byte)AsymmetricKeyType.Rsa4096);
            bw.Write(true);

            bw.Write(pp.Exponent.Length);
            bw.Write(pp.Exponent);
            bw.Write(pp.Modulus.Length);
            bw.Write(pp.Modulus);
            bw.Write(pp.D.Length);
            bw.Write(pp.D);
            bw.Write(pp.DP.Length);
            bw.Write(pp.DP);
            bw.Write(pp.DQ.Length);
            bw.Write(pp.DQ);
            bw.Write(pp.P.Length);
            bw.Write(pp.P);
            bw.Write(pp.Q.Length);
            bw.Write(pp.Q);
            bw.Write(pp.InverseQ.Length);
            bw.Write(pp.InverseQ);
            bw.Flush();
            return ms.ToArray();
        }
    }
}
