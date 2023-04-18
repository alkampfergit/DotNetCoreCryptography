using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace DotNetCoreCryptographyCore
{
    public static class AsymmetricEncryptionUtils
    {
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
            if (serializedRsaKey[0] != (byte)AsymmetricKeyType.Rsa4096)
            {
                throw new CryptographicException("Serialized key is not RSA 4096 bits");
            }

            using var ms = new MemoryStream(serializedRsaKey);
            using var br = new BinaryReader(ms);

            RSAParameters pp = new RSAParameters();

            br.ReadByte();
            hasPrivateKey = br.ReadBoolean();
            var exponentLength = br.ReadInt32();
            pp.Exponent = br.ReadBytes(exponentLength);
            var modulusLength = br.ReadInt32();
            pp.Modulus = br.ReadBytes(modulusLength);

            if (hasPrivateKey)
            {
                var dLength = br.ReadInt32();
                pp.D = br.ReadBytes(dLength);
                var dpLength = br.ReadInt32();
                pp.DP = br.ReadBytes(dpLength);
                var dqLength = br.ReadInt32();
                pp.DQ = br.ReadBytes(dqLength);

                var pLength = br.ReadInt32();
                pp.P = br.ReadBytes(pLength);
                var qLength = br.ReadInt32();
                pp.Q = br.ReadBytes(qLength);
                var inverseQLength = br.ReadInt32();
                pp.InverseQ = br.ReadBytes(inverseQLength);
            }
            return RSA.Create(pp);
        }
    }
}
