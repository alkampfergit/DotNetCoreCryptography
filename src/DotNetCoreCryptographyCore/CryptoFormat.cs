using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Constants and helpers shared by the authenticated (v2) serialization formats.
    /// v1 streams carry no marker, so v2 data is detected by the leading magic
    /// sequence. The magic is chosen so it cannot collide with plausible v1 data:
    /// read as the little-endian length that opens every v1 envelope it is roughly
    /// 37.9 million, far beyond any real wrapped-key length or key number.
    /// </summary>
    internal static class CryptoFormat
    {
        /// <summary>"DNC" followed by the format version (2).</summary>
        public static readonly byte[] V2Magic = { 0x44, 0x4E, 0x43, 0x02 };

        public const int MagicLength = 4;

        /// <summary>
        /// Upper bound for the wrapped-key length field of the envelope formats.
        /// Real wrapped keys are at most ~600 bytes (RSA-4096); the bound exists to
        /// stop an attacker-controlled length from driving a multi-GB allocation.
        /// </summary>
        public const int MaxWrappedKeyLength = 8 * 1024;

        public static bool StartsWithV2Magic(ReadOnlySpan<byte> data)
        {
            return data.Length >= MagicLength && data.Slice(0, MagicLength).SequenceEqual(V2Magic);
        }

        /// <summary>
        /// Builds the v2 envelope header <c>[magic][int32 wrapped-key length][wrapped key]</c>.
        /// The whole header is passed as associated data to the payload encryption, so
        /// tampering with any of its bytes makes decryption fail.
        /// </summary>
        public static byte[] BuildV2EnvelopeHeader(byte[] wrappedKey)
        {
            var header = new byte[MagicLength + sizeof(int) + wrappedKey.Length];
            V2Magic.CopyTo(header, 0);
            BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(MagicLength), wrappedKey.Length);
            wrappedKey.CopyTo(header, MagicLength + sizeof(int));
            return header;
        }

        public static void ValidateWrappedKeyLength(int length)
        {
            if (length <= 0 || length > MaxWrappedKeyLength)
            {
                throw new CryptographicException("Invalid wrapped key length");
            }
        }

        /// <summary>
        /// Creates an <see cref="Aes"/> instance loaded with the raw material of
        /// <paramref name="kek"/>, to be used for RFC 5649 AES key wrapping
        /// (<see cref="Aes.EncryptKeyWrapPadded(byte[])"/> and companions).
        /// </summary>
        public static Aes CreateKeyWrapAes(EncryptionKey kek)
        {
            var material = kek.ExportRawKeyMaterial();
            try
            {
                var aes = Aes.Create();
                aes.Key = material;
                return aes;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(material);
            }
        }

        /// <summary>
        /// Uniform decryption failure: callers must not be able to distinguish why
        /// decryption failed (bad tag, truncation, malformed header, ...) from the
        /// exception type or message. The original error is preserved as inner
        /// exception for in-process diagnostics only.
        /// </summary>
        public static CryptographicException DecryptionFailed(Exception inner)
        {
            return new CryptographicException("Decryption failed.", inner);
        }
    }
}
