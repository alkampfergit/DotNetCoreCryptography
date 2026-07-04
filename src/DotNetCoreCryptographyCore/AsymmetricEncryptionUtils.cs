using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    public static class AsymmetricEncryptionUtils
    {
        private const int Rsa4096ModulusBytes = 512;
        private const int Rsa4096PrimeBytes = 256;
        private const int MaxRsaExponentBytes = 8;
        private const string InvalidSerializedRsaKeyMessage = "Serialized RSA key is invalid";

        public static bool KeyEqual(this RSAParameters p1, RSAParameters p2) 
        {
            return p1.D.SequenceEqual(p2.D)
                && p1.DP.SequenceEqual(p2.DP)
                && p1.DQ.SequenceEqual(p2.DQ)
                && p1.Exponent.SequenceEqual(p2.Exponent)
                && p1.Modulus.SequenceEqual(p2.Modulus)
                && p1.P.SequenceEqual(p2.P)
                && p1.Q.SequenceEqual(p2.Q)
                && p1.InverseQ.SequenceEqual(p2.InverseQ);
        }

        /// <summary>
        /// Serialize an RSA key into a byte array, Serialized version
        /// contains the private key.
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="includePrivatePart"></param>
        /// <returns></returns>
        public static byte[] Serialize(this RSA rsa, bool includePrivatePart)
        {
            if (rsa.KeySize != 4096)
            {
                throw new ArgumentException("Rsa key size should be 4096 bits");
            }

            var pp = rsa.ExportParameters(includePrivatePart);
            
            //we need to serialize private parameters
            using var ms = new MemoryStream(4096);
            using var bw = new BinaryWriter(ms);

            bw.Write((byte)AsymmetricKeyType.Rsa4096);
            bw.Write(includePrivatePart);

            bw.Write(pp.Exponent.Length);
            bw.Write(pp.Exponent);
            bw.Write(pp.Modulus.Length);
            bw.Write(pp.Modulus);

            if (includePrivatePart)
            {
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
            }
            bw.Flush();
            return ms.ToArray();
        }

        public static RSA DeserializeToRsa(this byte[] serializedRsaKey, out Boolean hasPrivateKey)
        {
            if (serializedRsaKey is null || serializedRsaKey.Length < 2)
            {
                throw new CryptographicException(InvalidSerializedRsaKeyMessage);
            }

            if (serializedRsaKey[0] != (byte)AsymmetricKeyType.Rsa4096)
            {
                throw new CryptographicException("Serialized key is not RSA 4096 bits");
            }

            try
            {
                using var ms = new MemoryStream(serializedRsaKey);
                using var br = new BinaryReader(ms);

                RSAParameters pp = new RSAParameters();

                br.ReadByte();
                hasPrivateKey = br.ReadBoolean();
                pp.Exponent = ReadBoundedBytes(br, MaxRsaExponentBytes);
                pp.Modulus = ReadBoundedBytes(br, Rsa4096ModulusBytes);

                if (hasPrivateKey)
                {
                    pp.D = ReadBoundedBytes(br, Rsa4096ModulusBytes);
                    pp.DP = ReadBoundedBytes(br, Rsa4096PrimeBytes);
                    pp.DQ = ReadBoundedBytes(br, Rsa4096PrimeBytes);
                    pp.P = ReadBoundedBytes(br, Rsa4096PrimeBytes);
                    pp.Q = ReadBoundedBytes(br, Rsa4096PrimeBytes);
                    pp.InverseQ = ReadBoundedBytes(br, Rsa4096PrimeBytes);
                }

                var rsa = RSA.Create(pp);
                // Reject a strength downgrade: a blob carrying a short modulus would
                // otherwise yield a weak key still advertised as Rsa4096 (SEC-5).
                if (rsa.KeySize != 4096)
                {
                    rsa.Dispose();
                    throw new CryptographicException("Deserialized RSA key is not 4096 bits");
                }
                return rsa;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex) when (ex is EndOfStreamException || ex is IOException || ex is ArgumentException)
            {
                throw new CryptographicException(InvalidSerializedRsaKeyMessage, ex);
            }
        }

        private static byte[] ReadBoundedBytes(BinaryReader br, int maxLength)
        {
            var length = br.ReadInt32();
            if (length <= 0 || length > maxLength || length > br.BaseStream.Length - br.BaseStream.Position)
            {
                throw new CryptographicException(InvalidSerializedRsaKeyMessage);
            }

            var value = br.ReadBytes(length);
            if (value.Length != length)
            {
                throw new CryptographicException(InvalidSerializedRsaKeyMessage);
            }

            return value;
        }
    }
}
