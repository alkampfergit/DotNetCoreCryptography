using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    public class RsaEncryptionKey : AsymmetricEncryptionKey
    {
        private readonly RSA _key;

        public RsaEncryptionKey()
        {
            _key = RSA.Create(4096);
            HasPrivateKey = true;
        }

        public RsaEncryptionKey(byte[] serializedKey)
        {
            _key = serializedKey.DeserializeToRsa(out var hasPrivateKey);
            HasPrivateKey = hasPrivateKey;
        }

        public override byte[] Serialize()
        {
            return _key.Serialize(true);
        }

        public override byte[] SerializePublicKey()
        {
            return _key.Serialize(false);
        }

        public override bool IsEqualTo(AsymmetricEncryptionKey other)
        {
            if (other is RsaEncryptionKey rsaKey)
            {
                return HasPrivateKey == rsaKey.HasPrivateKey
                    && _key.ExportParameters(HasPrivateKey).KeyEqual(rsaKey._key.ExportParameters(HasPrivateKey));

            }
            return false;
        }

        protected override void OnDispose(bool disposing)
        {
            if (disposing)
            {
                _key.Dispose();
            }
        }

        public override byte[] Encrypt(byte[] data)
        {
            return _key.Encrypt(data, RSAEncryptionPadding.OaepSHA512);
        }

        public override byte[] Decrypt(byte[] encryptedData)
        {
            return _key.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA512);
        }
    }
}
