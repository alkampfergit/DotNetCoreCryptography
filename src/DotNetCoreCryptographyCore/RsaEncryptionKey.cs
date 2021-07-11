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

        public bool HasPrivateKey { get; private set; }

        public override byte[] Serialize()
        {
            return _key.Serialize(true);
        }

        public override byte[] SerializePublicKey()
        {
            return _key.Serialize(false);
        }

        public bool IsEqualTo(RsaEncryptionKey other)
        {
            return HasPrivateKey == other.HasPrivateKey
                && _key.ExportParameters(HasPrivateKey).KeyEqual(other._key.ExportParameters(HasPrivateKey));
        }

        protected override void OnDispose(bool disposing)
        {
            if (disposing)
            {
                _key.Dispose();
            }
        }
    }
}
