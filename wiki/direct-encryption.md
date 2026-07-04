# Direct Symmetric and Password Encryption

`StaticEncryptor` contains helpers for encrypting streams, byte arrays, and
strings when the caller already has the key or wants password-based encryption.

## Symmetric Key Helpers

```csharp
using System.IO;
using DotNetCoreCryptographyCore;

using var key = EncryptionKey.CreateDefault();

await using var source = File.OpenRead("message.txt");
await using var encrypted = File.Create("message.enc");
await StaticEncryptor.EncryptAsync(source, encrypted, key);

await using var encryptedInput = File.OpenRead("message.enc");
await using var decrypted = File.Create("message.out.txt");
await StaticEncryptor.DecryptAsync(encryptedInput, decrypted, key);
```

String helpers return Base64:

```csharp
using var key = EncryptionKey.CreateDefault();

var encrypted = StaticEncryptor.Encrypt("secret text", key);
var decrypted = StaticEncryptor.Decrypt(encrypted, key);
```

## Password Helpers

```csharp
var encrypted = await StaticEncryptor.AesEncryptWithPasswordAsync(
    data,
    password);

var decrypted = await StaticEncryptor.AesDecryptWithPasswordAsync(
    encrypted,
    password);
```

Current password encryption writes:

```text
[magic][16-byte salt][AES-GCM payload]
```

The password key is derived with PBKDF2-HMAC-SHA256 and 600,000 iterations. The
header is authenticated as associated data.

## Legacy Compatibility

The library can still decrypt legacy v1 AES-CBC data. The transform-based APIs
and legacy key type are marked obsolete and should not be used for new data.
