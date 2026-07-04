# DotNetCoreCryptography

DotNetCoreCryptography is a .NET library for authenticated symmetric encryption
and envelope encryption.

The default data path uses a fresh AES-256-GCM data-encryption key for each
payload. For envelope encryption, that data key is wrapped separately through an
`IKeyEncryptor` implementation, such as a local developer key, a folder-backed
key store, an asymmetric key, or Azure Key Vault.

## Quick Start

Use `SecureEncryptor` when you want the library to generate a one-time
symmetric key for the data and protect only that key with a key-encryption key
(KEK).

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

await using var plaintext = File.OpenRead("message.txt");
await using var encrypted = File.Create("message.enc");
await encryptor.Encrypt(plaintext, encrypted);

await using var encryptedInput = File.OpenRead("message.enc");
await using var decrypted = File.Create("message.out.txt");
await encryptor.Decrypt(encryptedInput, decrypted);
```

For simple direct encryption where you already manage the symmetric key:

```csharp
using DotNetCoreCryptographyCore;

using var key = EncryptionKey.CreateDefault();
var encrypted = StaticEncryptor.Encrypt("secret text", key);
var decrypted = StaticEncryptor.Decrypt(encrypted, key);
```

## Documentation

The detailed usage guide lives in the repository wiki folder:

- [Wiki index](wiki/README.md)
- [Quick start](wiki/quick-start.md)
- [Envelope encryption](wiki/envelope-encryption.md)
- [Key encryptors and KEKs](wiki/key-encryptors.md)
- [Direct symmetric and password encryption](wiki/direct-encryption.md)
- [Asymmetric hybrid encryption](wiki/asymmetric-encryption.md)
- [Formats and security notes](wiki/formats-and-security.md)
- [Testing and build notes](wiki/testing.md)

## Choosing an API

- Prefer `SecureEncryptor` plus an `IKeyEncryptor` for application data.
- Prefer Azure Key Vault or another external KEK provider for production key
  protection.
- Use `DeveloperKeyEncryptor` only for local development. Its master key is DPAPI-
  protected on Windows; on Linux/macOS it is cleartext and requires
  `allowUnencryptedKeyStore: true`.
- Use `FolderBasedKeyEncryptor` only when you can protect the key folder and, in
  normal deployments, configure a password. Passwordless (cleartext) storage
  requires an explicit `allowUnencryptedKeys: true` opt-in.
- Use `StaticEncryptor` for direct symmetric-key scenarios or password-based
  helpers.
- Legacy AES-CBC APIs are retained only for backward-compatible decryption.

## Running Tests

```shell
dotnet test src/DotNetCoreCryptography.sln
```

Some tests use an Azure Key Vault instance. To run those successfully, set:

```shell
AZURE_TENANT_ID=# Tenant where the application is installed
AZURE_CLIENT_SECRET=# Client secret for the Azure application
AZURE_CLIENT_ID=# Client id for the Azure application
```

See [testing notes](wiki/testing.md) for more detail.
