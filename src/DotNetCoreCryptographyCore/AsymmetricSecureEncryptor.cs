using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// Hybrid encryption: a fresh symmetric key encrypts the payload and is itself
    /// wrapped with an <see cref="AsymmetricEncryptionKey"/> (RSA-OAEP). Envelope
    /// format v2 is the same as <see cref="SecureEncryptor"/>:
    /// <c>[magic][int32 wrapped-key length][wrapped key][AES-GCM payload]</c> with
    /// the header authenticated as associated data. Legacy v1 (AES-CBC) streams are
    /// still decrypted.
    /// </summary>
    public static class AsymmetricSecureEncryptor
    {
        /// <summary>
        /// Encrypt a stream generating a symmetric key, then encrypt with
        /// a <see cref="AsymmetricEncryptionKey"/> and store the encrypted key in destination
        /// stream.
        /// </summary>
        /// <param name="asymmetricKey"></param>
        /// <param name="streamToEncrypt"></param>
        /// <param name="destinationStream"></param>
        /// <returns></returns>
        public async static Task Encrypt(
            AsymmetricEncryptionKey asymmetricKey,
            Stream streamToEncrypt,
            Stream destinationStream)
        {
            //to encrypt we need to generate a new key
            using var key = EncryptionKey.CreateDefault();

            //now we want to be able to store it securely; wipe the plaintext
            //serialized key once it has been wrapped (SEC-8).
            var serializedKey = key.Serialize();
            byte[] encryptedKey;
            try
            {
                encryptedKey = asymmetricKey.Encrypt(serializedKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serializedKey);
            }

            //write the envelope header, then encrypt binding the header as
            //associated data so it cannot be tampered with.
            var header = CryptoFormat.BuildV2EnvelopeHeader(encryptedKey);
            await destinationStream.WriteAsync(header).ConfigureAwait(false);
            await key.EncryptAsync(streamToEncrypt, destinationStream, associatedData: header).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt a stream encrypted by <see cref="Encrypt(AsymmetricEncryptionKey, Stream, Stream)"/>
        /// method. Encrypted stream contains an header with the symmetric key used to
        /// encrypt the stream, wrapped with the asymmetric key. Any modification of the
        /// stream makes this method fail with a <see cref="System.Security.Cryptography.CryptographicException"/>.
        /// </summary>
        /// <param name="asymmetricKey"></param>
        /// <param name="sourceEncryptedStream"></param>
        /// <param name="destinationDecryptedStream"></param>
        /// <returns></returns>
        public static async Task Decrypt(
            AsymmetricEncryptionKey asymmetricKey,
            Stream sourceEncryptedStream,
            Stream destinationDecryptedStream)
        {
            try
            {
                var prefix = new byte[CryptoFormat.MagicLength];
                await sourceEncryptedStream.ReadExactlyAsync(prefix).ConfigureAwait(false);
                if (CryptoFormat.StartsWithV2Magic(prefix))
                {
                    var lengthBuffer = new byte[sizeof(int)];
                    await sourceEncryptedStream.ReadExactlyAsync(lengthBuffer).ConfigureAwait(false);
                    var wrappedKeyLength = BinaryPrimitives.ReadInt32LittleEndian(lengthBuffer);
                    CryptoFormat.ValidateWrappedKeyLength(wrappedKeyLength);
                    var wrappedKey = new byte[wrappedKeyLength];
                    await sourceEncryptedStream.ReadExactlyAsync(wrappedKey).ConfigureAwait(false);

                    var header = CryptoFormat.BuildV2EnvelopeHeader(wrappedKey);
                    var serializedKey = asymmetricKey.Decrypt(wrappedKey);
                    try
                    {
                        using var key = EncryptionKey.CreateFromSerializedVersion(serializedKey);
                        await key.DecryptAsync(sourceEncryptedStream, destinationDecryptedStream, associatedData: header).ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(serializedKey);
                    }
                }
                else
                {
                    //legacy v1 envelope: the four bytes just read are the little-endian
                    //length of the wrapped key, followed by wrapped key and CBC payload.
                    var wrappedKeyLength = BinaryPrimitives.ReadInt32LittleEndian(prefix);
                    CryptoFormat.ValidateWrappedKeyLength(wrappedKeyLength);
                    var wrappedKey = new byte[wrappedKeyLength];
                    await sourceEncryptedStream.ReadExactlyAsync(wrappedKey).ConfigureAwait(false);

                    var serializedKey = asymmetricKey.Decrypt(wrappedKey);
                    try
                    {
                        using var key = EncryptionKey.CreateFromSerializedVersion(serializedKey);
                        await key.DecryptAsync(sourceEncryptedStream, destinationDecryptedStream).ConfigureAwait(false);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(serializedKey);
                    }
                }
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }
    }
}
