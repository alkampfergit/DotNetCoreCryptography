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
    }
}
