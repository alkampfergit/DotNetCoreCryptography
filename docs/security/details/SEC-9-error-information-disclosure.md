# SEC-9 — Information Disclosure via Errors / Poor Exception Typing

| | |
|---|---|
| **Finding ID** | SEC-9 |
| **Severity** | Low |
| **CWE** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) (Generation of Error Message Containing Sensitive Information), [CWE-20](https://cwe.mitre.org/data/definitions/20.html) (Improper Input Validation) |
| **Component** | `FolderBasedKeyEncryptor`, `EncryptionKey`, `AsymmetricEncryptionKey` |
| **Status** | Open |
| **Analysis date** | 2026-07-03 |
| **Commit** | `9b0f088` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-5](SEC-5-key-deserialization-validation.md) (both concern deserialization robustness).

## Summary

Two related robustness issues:

1. A tampered or unknown key number in `FolderBasedKeyEncryptor` surfaces as a
   `FileNotFoundException`/`DirectoryNotFoundException` whose message **leaks the on-disk
   key-folder path**.
2. The public deserialization factories index `serializedKey[0]` with **no null/empty guard**,
   so malformed input throws `NullReferenceException` / `IndexOutOfRangeException` instead of a
   deliberate, catchable `CryptographicException`.

## Affected code

`src/DotNetCoreCryptographyCore/Concrete/FolderBasedKeyEncryptor.cs`

```csharp
public async Task<EncryptionKey> DecryptAsync(byte[] encryptedKey)
{
    using var sourceMs = new MemoryStream(encryptedKey);
    var buffer = new byte[4];
    sourceMs.Read(buffer, 0, 4);
    var decryptionKey = GetKey(BitConverter.ToInt32(buffer));   // unvalidated key number
    // ...
}

private EncryptionKey GetKey(int keyNumber)
{
    if (!_keys.TryGetValue(keyNumber, out var key))
    {
        var keyName = Path.Combine(_keyMaterialFolderStore, $"{keyNumber}.key");
        var encryptedSerializedKey = File.ReadAllBytes(keyName);  // FileNotFound leaks full path
        // ...
    }
    return key;
}
```

`src/DotNetCoreCryptographyCore/EncryptionKey.cs`

```csharp
public static EncryptionKey CreateFromSerializedVersion(byte[] serializedKey)
{
    var keyType = (KeyType)serializedKey[0];   // null -> NRE; empty -> IndexOutOfRangeException
    // ...
}
```

`src/DotNetCoreCryptographyCore/AsymmetricEncryptionKey.cs` has the same unguarded
`serializedKey[0]` pattern.

## Root cause

Input from disk and from callers is consumed without boundary validation, and file-access
exceptions (which embed the path) are allowed to propagate to the caller. The deserialization
entry points do not normalise their failure mode to a single crypto-specific exception type.

## Exploitation

- **Path disclosure (CWE-209).** An attacker who can submit a crafted `encryptedKey` blob to
  `DecryptAsync` (directly, or via `SecureEncryptor`) can choose a key number that does not
  exist; the resulting `FileNotFoundException`/`DirectoryNotFoundException` message contains
  the absolute key-storage path (e.g. `C:\keys\9999.key` or `/var/app/keys/9999.key`). If that
  message is surfaced in an API response or log accessible to the attacker, it reveals internal
  filesystem layout useful for further attacks. (The key number is an `int` interpolated into
  the filename, so there is **no path traversal** — the exposure is limited to the folder path.)
- **Ungraceful failures (CWE-20).** `CreateFromSerializedVersion(null)` throws
  `NullReferenceException`; an empty array throws `IndexOutOfRangeException`. This is realistic:
  `DeveloperKeyEncryptor` reads a key file directly with `File.ReadAllBytes`, so an empty or
  truncated key file (e.g. after an interrupted `File.WriteAllBytes`, then `File.Exists` skips
  regeneration) reaches this path. Callers that catch `CryptographicException`/`ArgumentException`
  do not catch these, so the error escapes unexpectedly.

## Impact

Low: information disclosure limited to a filesystem path, plus poor error hygiene. No direct
compromise of confidentiality or integrity.

## Remediation

**Validate the key number and translate file-access failures:**

```csharp
if (encryptedKey is null || encryptedKey.Length < 5)
    throw new CryptographicException("Malformed encrypted key blob.");

int keyNumber = BinaryPrimitives.ReadInt32LittleEndian(encryptedKey);
// ...
try
{
    encryptedSerializedKey = File.ReadAllBytes(keyName);
}
catch (IOException)   // FileNotFound/DirectoryNotFound derive from IOException
{
    throw new CryptographicException("Unknown or unavailable key.");  // no path in message
}
```

**Guard the deserialization factories:**

```csharp
public static EncryptionKey CreateFromSerializedVersion(byte[] serializedKey)
{
    ArgumentNullException.ThrowIfNull(serializedKey);
    if (serializedKey.Length < 1)
        throw new CryptographicException("Invalid serialized key.");
    var keyType = (KeyType)serializedKey[0];
    // ...
}
```

Also read the 4-byte key number with `ReadExactly`/`BinaryPrimitives` rather than an unchecked
`Stream.Read` (consistent with [SEC-6](SEC-6-partial-read-iv-salt.md)).

## Verification / tests to add

- `DecryptAsync` with a blob referencing a non-existent key number throws `CryptographicException`
  whose message contains no filesystem path.
- `CreateFromSerializedVersion(null)` and `CreateFromSerializedVersion(Array.Empty<byte>())`
  throw `ArgumentNullException` / `CryptographicException` respectively.

## References

- CWE-209, CWE-20 (linked above).
- .NET API: `System.Buffers.Binary.BinaryPrimitives`, `Stream.ReadExactly`.
