using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading.Tasks;

namespace DotNetCoreCryptographyCore
{
    /// <summary>
    /// <para>
    /// A class capable to encrypt stream in a secure way using a
    /// <see cref="IKeyEncryptor"/> to protect key used to encrypt.
    /// </para>
    /// <para>
    /// It will use by default a new <see cref="EncryptionKey"/> each
    /// time to guarantee maximum security.
    /// </para>
    /// <para>
    /// Envelope format v2: <c>[magic][int32 wrapped-key length][wrapped key][AES-GCM payload]</c>.
    /// The whole header is authenticated as associated data of the payload, so any
    /// modification of the envelope — header included — makes decryption fail.
    /// Streams produced by previous versions (v1, AES-CBC) are still decrypted.
    /// </para>
    /// </summary>
    public class SecureEncryptor
    {
        private readonly IKeyEncryptor _keyVaultStore;

        public SecureEncryptor(IKeyEncryptor keyVaultStore)
        {
            _keyVaultStore = keyVaultStore;
        }

        /// <summary>
        /// Encrypt a stream generating a symmetric key, then encrypt with
        /// a <see cref="IKeyEncryptor"/> and store the encrypted key in destination
        /// stream.
        /// </summary>
        /// <param name="streamToEncrypt"></param>
        /// <param name="destinationStream"></param>
        /// <returns></returns>
        public async Task Encrypt(Stream streamToEncrypt, Stream destinationStream)
        {
            //to encrypt we need to generate a new key
            using var key = EncryptionKey.CreateDefault();

            //now we want to be able to store it securely
            var encryptedKey = await _keyVaultStore.EncryptAsync(key).ConfigureAwait(false);

            //write the envelope header, then encrypt binding the header as
            //associated data so it cannot be tampered with.
            var header = CryptoFormat.BuildV2EnvelopeHeader(encryptedKey);
            await destinationStream.WriteAsync(header).ConfigureAwait(false);
            await key.EncryptAsync(streamToEncrypt, destinationStream, associatedData: header).ConfigureAwait(false);
        }

        /// <summary>
        /// Decrypt a stream encrypted by <see cref="Encrypt(Stream, Stream)"/> method. Encrypted
        /// stream contains an header that contains the key used to encrypt the stream, the
        /// key is encrypted using <see cref="IKeyEncryptor"/>. Any modification of the
        /// stream makes this method fail with a <see cref="System.Security.Cryptography.CryptographicException"/>.
        /// </summary>
        /// <param name="sourceEncryptedStream"></param>
        /// <param name="destinationDecryptedStream"></param>
        /// <returns></returns>
        public async Task Decrypt(Stream sourceEncryptedStream, Stream destinationDecryptedStream)
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
                    using var key = await _keyVaultStore.DecryptAsync(wrappedKey).ConfigureAwait(false);
                    await key.DecryptAsync(sourceEncryptedStream, destinationDecryptedStream, associatedData: header).ConfigureAwait(false);
                }
                else
                {
                    //legacy v1 envelope: the four bytes just read are the little-endian
                    //length of the wrapped key, followed by wrapped key and CBC payload.
                    var wrappedKeyLength = BinaryPrimitives.ReadInt32LittleEndian(prefix);
                    CryptoFormat.ValidateWrappedKeyLength(wrappedKeyLength);
                    var wrappedKey = new byte[wrappedKeyLength];
                    await sourceEncryptedStream.ReadExactlyAsync(wrappedKey).ConfigureAwait(false);

                    using var key = await _keyVaultStore.DecryptAsync(wrappedKey).ConfigureAwait(false);
                    await key.DecryptAsync(sourceEncryptedStream, destinationDecryptedStream).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                throw CryptoFormat.DecryptionFailed(ex);
            }
        }
    }
}
