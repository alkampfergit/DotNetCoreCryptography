using DotNetCoreCryptography.Azure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace DotNetCoreCryptography.Tests.Azure
{
    public class AzureKeyVaultStoreTests
    {
        private AzureKeyVaultStore _sut;

        private void GenerateSut() 
        {
            _sut = new AzureKeyVaultStore("https://test-kv-alk.vault.azure.net/", "test");
        }

        [Fact]
        public void Can_encrypt_then_decrypt() 
        {
            GenerateSut();
        }
    }
}
