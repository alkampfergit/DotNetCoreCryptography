# Envelope Encryption

`SecureEncryptor` is the primary high-level encryption API.

## What It Does

For each call to `Encrypt`:

1. Create a fresh `EncryptionKey` with `EncryptionKey.CreateDefault()`.
2. Ask the configured `IKeyEncryptor` to encrypt that key.
3. Write an envelope header containing the wrapped key.
4. Encrypt the payload with the fresh data key.

For each call to `Decrypt`:

1. Read the envelope header.
2. Extract the wrapped key.
3. Ask the same kind of `IKeyEncryptor` to decrypt the wrapped key.
4. Use the recovered data key to decrypt the payload.

## Format

Current v2 envelope format:

```text
[magic][int32 wrapped-key length][wrapped key][AES-GCM payload]
```

The envelope header is authenticated as AES-GCM associated data. If a caller
changes the magic, wrapped-key length, wrapped key, nonce, ciphertext, or tag,
decryption fails with a `CryptographicException`.

## Example

```csharp
using System.IO;
using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;

var keyEncryptor = new FolderBasedKeyEncryptor("./keys", "key-store-password");
var secureEncryptor = new SecureEncryptor(keyEncryptor);

await using var input = File.OpenRead("plain.bin");
await using var output = File.Create("plain.bin.enc");
await secureEncryptor.Encrypt(input, output);

await using var encrypted = File.OpenRead("plain.bin.enc");
await using var decrypted = File.Create("plain.bin.dec");
await secureEncryptor.Decrypt(encrypted, decrypted);
```

## When To Use It

Use this for normal application payload encryption, especially when many objects
need independent data keys but a smaller number of KEKs must be managed.

This model is also the place to integrate HSMs, cloud key vaults, or other
external key-management systems: implement `IKeyEncryptor` and pass that
implementation to `SecureEncryptor`.
