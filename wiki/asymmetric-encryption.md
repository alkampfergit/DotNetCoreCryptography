# Asymmetric Hybrid Encryption

`AsymmetricSecureEncryptor` performs envelope encryption directly with an
`AsymmetricEncryptionKey`.

It uses the same envelope shape as `SecureEncryptor`:

```text
[magic][int32 wrapped-key length][wrapped key][AES-GCM payload]
```

The difference is that the data key is wrapped by the asymmetric key instead of
an `IKeyEncryptor` implementation.

The built-in `RsaEncryptionKey` wraps data with RSA OAEP-SHA512.

## Example

```csharp
using System.IO;
using DotNetCoreCryptographyCore;

using var privateKey = new RsaEncryptionKey();
using var publicKey = AsymmetricEncryptionKey.CreateFromSerializedVersion(
    privateKey.SerializePublicKey());

await using var plaintext = File.OpenRead("message.txt");
await using var encrypted = File.Create("message.enc");
await AsymmetricSecureEncryptor.Encrypt(publicKey, plaintext, encrypted);

await using var encryptedInput = File.OpenRead("message.enc");
await using var decrypted = File.Create("message.out.txt");
await AsymmetricSecureEncryptor.Decrypt(privateKey, encryptedInput, decrypted);
```

## Key Serialization

`SerializePublicKey()` returns only the public portion and can be shared with
encrypting callers.

`Serialize()` returns both private and public key material. Treat that output as
secret key material and store it only in a secure location.

## When To Use It

Use this API when the recipient has an RSA private key and producers should need
only the public key to encrypt. For cloud/HSM-managed keys, prefer implementing
or using an `IKeyEncryptor` so the private key remains in the managed service.
