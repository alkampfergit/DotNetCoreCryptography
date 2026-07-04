# DotNetCoreCryptography Wiki

This wiki explains how to use DotNetCoreCryptography and how the main
cryptographic building blocks fit together.

## Start Here

- [Quick start](quick-start.md): install, encrypt, decrypt, and choose the right
  entry point.
- [Envelope encryption](envelope-encryption.md): the recommended model for
  application payloads.
- [Key encryptors and KEKs](key-encryptors.md): how data keys are protected.

## API Guides

- [Direct symmetric and password encryption](direct-encryption.md)
- [Asymmetric hybrid encryption](asymmetric-encryption.md)
- [Formats and security notes](formats-and-security.md)
- [Testing and build notes](testing.md)

## Recommended Usage

For new application data, use `SecureEncryptor` with an `IKeyEncryptor`.
`SecureEncryptor` creates a fresh AES-256-GCM data key for each encryption
operation, encrypts the payload with that key, wraps the data key, and stores the
wrapped key in the envelope header.

Use direct `StaticEncryptor` APIs only when your application already has a safe
place to manage the symmetric key or when you specifically need the
password-based helpers.

## Source Map

- `src/DotNetCoreCryptographyCore/SecureEncryptor.cs`: envelope encryption.
- `src/DotNetCoreCryptographyCore/IKeyEncryptor.cs`: key wrapping abstraction.
- `src/DotNetCoreCryptographyCore/Concrete/DeveloperKeyEncryptor.cs`: local
  developer KEK implementation.
- `src/DotNetCoreCryptographyCore/Concrete/FolderBasedKeyEncryptor.cs`:
  folder-backed KEK implementation.
- `src/DotNetCoreCryptography.Azure/AzureKeyVaultStoreKeyEncryptor.cs`: Azure
  Key Vault KEK implementation.
- `src/DotNetCoreCryptographyCore/StaticEncryptor.cs`: direct symmetric and
  password helpers.
- `src/DotNetCoreCryptographyCore/AsymmetricSecureEncryptor.cs`: RSA hybrid
  envelope encryption.
