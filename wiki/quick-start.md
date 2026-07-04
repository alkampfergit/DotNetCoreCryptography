# Quick Start

## Target Framework

The projects currently target `net10.0` through `Directory.Build.props`.

## Envelope Encryption

Envelope encryption is the main API for application payloads. It generates a new
symmetric data key for each payload and protects that key separately.

```csharp
using System;
using System.IO;
using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;

var keyEncryptor = new FolderBasedKeyEncryptor(
    keyMaterialFolderStore: "/var/app/crypto-keys",
    password: Environment.GetEnvironmentVariable("KEY_STORE_PASSWORD")
        ?? throw new InvalidOperationException("KEY_STORE_PASSWORD is not set."));

var encryptor = new SecureEncryptor(keyEncryptor);

await using var source = File.OpenRead("message.txt");
await using var encrypted = File.Create("message.enc");
await encryptor.Encrypt(source, encrypted);

await using var encryptedInput = File.OpenRead("message.enc");
await using var destination = File.Create("message.out.txt");
await encryptor.Decrypt(encryptedInput, destination);
```

The output contains both the wrapped data key and the AES-GCM payload. The
plaintext key is not written to the output stream.

## String Helpers

`SecureEncryptorExtensionMethods` adds string helpers that encode encrypted
bytes as hex.

```csharp
using DotNetCoreCryptographyCore;
using DotNetCoreCryptographyCore.Concrete;

// On Windows the master key is protected with DPAPI automatically.
// On Linux/macOS there is no OS key store, so the key is stored in cleartext and
// you must opt in explicitly:
var keyEncryptor = new DeveloperKeyEncryptor("./dev-keys", allowUnencryptedKeyStore: true);
var encryptor = new SecureEncryptor(keyEncryptor);

var encrypted = await encryptor.EncryptAsync("secret text");
var decrypted = await encryptor.DecryptAsync(encrypted);
```

`DeveloperKeyEncryptor` is for local development only. On Windows the master key is
encrypted at rest with DPAPI (current-user scope); on non-Windows platforms it is
stored in cleartext, which is why `allowUnencryptedKeyStore: true` is required there.

## Direct Symmetric Encryption

Use direct encryption when your application manages the key lifetime itself.

```csharp
using DotNetCoreCryptographyCore;

using var key = EncryptionKey.CreateDefault();

var encrypted = StaticEncryptor.Encrypt("secret text", key);
var decrypted = StaticEncryptor.Decrypt(encrypted, key);
```

`EncryptionKey.CreateDefault()` currently creates an AES-256-GCM key.

## Password Encryption

Password-based helpers derive an AES-256-GCM key from a password and random salt.

```csharp
using System.IO;
using DotNetCoreCryptographyCore;

var encrypted = StaticEncryptor.AesEncryptWithPassword(
    data: File.ReadAllBytes("message.txt"),
    password: "correct horse battery staple");

var decrypted = StaticEncryptor.AesDecryptWithPassword(
    encryptedData: encrypted,
    password: "correct horse battery staple");
```

Prefer a high-entropy KEK or external key vault for service data. Password-based
encryption is useful when the password is the real protection boundary.
