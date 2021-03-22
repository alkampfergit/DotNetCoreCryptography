using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Contains a <see cref="ICryptoTransform"/> as well as an optional prefix that should
    /// be saved to the head of the stream.
    /// </summary>
    public struct EncryptionKeyCryptoTransform
    {
        public EncryptionKeyCryptoTransform(ICryptoTransform cryptoTransform, byte[] streamHeader)
        {
            CryptoTransform = cryptoTransform;
            StreamHeader = streamHeader;
        }

        public ICryptoTransform CryptoTransform { get; set; }

        /// <summary>
        /// This information should be serialized into the head of the stream, and it is needed to 
        /// save variable part of the encryption (like IV for AES) in clear at the beginning of the stream.
        /// </summary>
        public byte[] StreamHeader { get; set; }
    }
}
