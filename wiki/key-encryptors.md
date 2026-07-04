# Key Encryptors and KEKs

`IKeyEncryptor` is the abstraction that protects data-encryption keys.

```csharp
public interface IKeyEncryptor
{
    Task<byte[]> EncryptAsync(EncryptionKey key);
    Task<EncryptionKey> DecryptAsync(byte[] encryptedKey);
}
```

The caller gives it an `EncryptionKey`; the implementation returns a protected
byte array. That protected value is stored inside the envelope header.

## DeveloperKeyEncryptor

`DeveloperKeyEncryptor` stores a single master key in a local folder and uses it
to wrap data keys.

Current v2 wrapped-key format:

```text
[magic][AES-KWP(serialized key)]
```

The implementation uses AES Key Wrap with Padding, RFC 5649, through
`EncryptKeyWrapPadded` and `DecryptKeyWrapPadded`.

Use this only for local development. The master key file
`developerKeyValueStore.key` and its folder are created with owner-only
permissions (`0600` / `0700` on Unix). On Windows the master key is encrypted at
rest with DPAPI (current-user scope). On non-Windows platforms there is no OS key
store, so the key is stored in cleartext and the constructor requires an explicit
opt-in:

```csharp
// Windows: DPAPI-protected automatically. Linux/macOS: cleartext, opt-in required.
var keyEncryptor = new DeveloperKeyEncryptor("./dev-keys", allowUnencryptedKeyStore: true);
```

## FolderBasedKeyEncryptor

`FolderBasedKeyEncryptor` stores numbered KEKs in a folder and records metadata
in `info.json`.

Current v2 wrapped-key format:

```text
[magic][int32 key-number][AES-KWP(serialized key)]
```

The key number identifies which folder-backed KEK should unwrap the data key.
`GenerateNewKey()` creates a new KEK and makes it the current wrapping key.

If a password is supplied, the KEK files themselves are protected with
`StaticEncryptor.AesEncryptWithPassword`. A passwordless store keeps the KEK files
in cleartext and therefore requires an explicit opt-in — otherwise the constructor
throws:

```csharp
// Passwordless (cleartext) storage must be acknowledged explicitly.
var keyEncryptor = new FolderBasedKeyEncryptor("./keys", password: "", allowUnencryptedKeys: true);
```

KEK files and `info.json` are written with owner-only permissions (`0600` on Unix),
and key files are created atomically (`FileMode.CreateNew`) so a concurrent creator
can never silently overwrite an existing key.

## AzureKeyVaultStoreKeyEncryptor

`AzureKeyVaultStoreKeyEncryptor` stores the KEK in Azure Key Vault. It retrieves
the configured key and encrypts or decrypts serialized data keys with
`RsaOaep256`.

```csharp
using DotNetCoreCryptography.Azure;
using DotNetCoreCryptographyCore;

var keyEncryptor = new AzureKeyVaultStoreKeyEncryptor(
    keyValueStoreAddress: "https://my-vault.vault.azure.net/",
    actualKeyName: "payload-kek");

var secureEncryptor = new SecureEncryptor(keyEncryptor);
```

Authentication uses `DefaultAzureCredential`, so the runtime environment must be
configured for Azure Identity.

## Custom Implementations

Create a custom `IKeyEncryptor` when the KEK lives in another system.

Implementation requirements:

- `EncryptAsync` must serialize and protect the supplied `EncryptionKey`.
- `DecryptAsync` must reverse the operation and return an `EncryptionKey`.
- The decryptor must understand every wrapped-key format it has previously
  emitted.
- The implementation should fail closed on tampering and avoid exposing detailed
  failure reasons to untrusted callers.
