# SEC-3 — Insecure Key Storage at Rest

| | |
|---|---|
| **Finding ID** | SEC-3 |
| **Severity** | High |
| **CWE** | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) (Cleartext Storage of Sensitive Information), [CWE-276](https://cwe.mitre.org/data/definitions/276.html) (Incorrect Default Permissions), [CWE-311](https://cwe.mitre.org/data/definitions/311.html) (Missing Encryption of Sensitive Data), [CWE-367](https://cwe.mitre.org/data/definitions/367.html) (TOCTOU Race Condition) |
| **Component** | `DeveloperKeyEncryptor`, `FolderBasedKeyEncryptor`, `InternalUtils` |
| **Status** | ✅ Remediated (see [Resolution](#resolution)) |
| **Analysis date** | 2026-07-03 |
| **Commit** | `9b0f088` (analysis); remediated on branch `feature/modernization` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-2](SEC-2-weak-kdf.md) (even password-protected key files become crackable once readable).

## Summary

Key-encryption keys are persisted to disk in ways that expose them to local attackers:

- `DeveloperKeyEncryptor` stores its master AES key **in cleartext**, always.
- `FolderBasedKeyEncryptor` stores key files **in cleartext** whenever the password is empty
  (an explicitly supported and tested mode).
- Key files and their containing directory are created with **default permissions**, which on
  Unix-like systems are typically world-/group-readable.
- Key creation uses a **`File.Exists` → `File.WriteAllBytes`** sequence with no atomicity,
  creating a time-of-check/time-of-use race.

## Affected code

### Cleartext master key + creation race — `DeveloperKeyEncryptor`

`src/DotNetCoreCryptographyCore/Concrete/DeveloperKeyEncryptor.cs`

```csharp
public DeveloperKeyEncryptor(string keyFolder)
{
    InternalUtils.EnsureDirectory(keyFolder);
    var keyName = Path.Combine(keyFolder, DeveloperKeyName);
    if (!File.Exists(keyName))                       // TOCTOU check ...
    {
        using var key = EncryptionKey.CreateDefault();
        File.WriteAllBytes(keyName, key.Serialize()); // ... use: cleartext key, default perms
    }
    _key = EncryptionKey.CreateFromSerializedVersion(File.ReadAllBytes(keyName));
}
```

### Cleartext-capable key files — `FolderBasedKeyEncryptor`

`src/DotNetCoreCryptographyCore/Concrete/FolderBasedKeyEncryptor.cs`

```csharp
private byte[] Encrypt(byte[] key)
{
    if (!String.IsNullOrEmpty(_password))
        return StaticEncryptor.AesEncryptWithPassword(key, _password);
    return key;                          // Key is unencrypted when no password
}
// ...
File.WriteAllBytes(keyName, encryptedSerializedKey);   // GenerateNewKey(), default perms
```

### Permissionless directory creation — `InternalUtils`

`src/DotNetCoreCryptographyCore/Utils/InternalUtils.cs`

```csharp
public static void EnsureDirectory(string directoryPath)
{
    if (!Directory.Exists(directoryPath))
        Directory.CreateDirectory(directoryPath);   // no UnixFileMode; default (umask) perms
}
```

## Root cause

The persistence code was written for a single-user developer machine and never set an
access-control policy for the key material. On Linux/macOS, `File.WriteAllBytes` creates files
with mode `0666 & ~umask` (commonly `0644`) inside a `0755` directory, both readable by other
local users. On Windows no restrictive ACL is applied. The developer store also has no fence
(warning, environment gate) preventing production use — only an XML-doc comment.

## Exploitation

**Scenario: multi-tenant / shared host (CWE-276 + CWE-312).**
1. A service using `DeveloperKeyEncryptor` (or a passwordless `FolderBasedKeyEncryptor`) runs
   on a shared Linux host, container with a shared volume, or CI runner.
2. Another local user (or a lower-privileged co-tenant) lists the key directory —
   world-readable — and reads `developerKeyValueStore.key` or `{n}.key` directly.
3. The file is the serialized AES key (cleartext), so the attacker immediately holds the KEK
   and decrypts everything. If the folder store used a password, the file is still readable
   and the attacker falls back to offline cracking per [SEC-2](SEC-2-weak-kdf.md).

**Scenario: creation race (CWE-367).**
Two processes construct a `DeveloperKeyEncryptor` for the same folder concurrently. Both pass
the `!File.Exists` check, both write, and one clobbers the other — or one reads a partially
written file. The result is two encryptors with different keys, each unable to decrypt the
other's output (data-availability failure).

## Impact

Local disclosure of the key-encryption key, which protects all data encrypted through the
instance. Requires local access (co-resident user, shared volume, or exfiltrated backup),
hence High rather than Critical.

## Remediation

### Restrict permissions at creation time (no chmod TOCTOU window)

```csharp
var options = new FileStreamOptions
{
    Mode = FileMode.CreateNew,                 // also fixes the overwrite race
    Access = FileAccess.Write,
};
if (!OperatingSystem.IsWindows())
    options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite; // 0600

using var fs = new FileStream(keyName, options);
fs.Write(serializedKey);
```

Create the directory owner-only too:

```csharp
if (OperatingSystem.IsWindows())
    Directory.CreateDirectory(path);
else
    Directory.CreateDirectory(path,
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); // 0700
```

Catch the `IOException` from `FileMode.CreateNew` on a race and re-read the existing key
instead of overwriting.

### Additional hardening

- On Windows, encrypt the developer key with **DPAPI** (`ProtectedData.Protect`, current-user
  scope) instead of storing it in cleartext.
- Never store `FolderBasedKeyEncryptor` keys unencrypted — require a password/KEK, or wrap
  them with a platform key store.
- Add a loud warning or explicit opt-in flag when `DeveloperKeyEncryptor` or a passwordless
  `FolderBasedKeyEncryptor` is instantiated, so production misuse is visible.

## Verification / tests to add

- On Unix, create a store and assert the key file mode is `0600` and the directory `0700`.
- Concurrent construction of two instances against the same folder must not corrupt or lose a
  key.

## Resolution

Remediated on branch `feature/modernization`. Changes:

**Permissions & atomicity (`InternalUtils`, `DeveloperKeyEncryptor`, `FolderBasedKeyEncryptor`).**
- `EnsureDirectory` now creates the key directory `0700` on Unix (owner-only); default ACL on Windows.
- New `WriteNewFileRestricted` writes key files via `FileStreamOptions { Mode = CreateNew, UnixCreateMode = 0600 }`.
  `CreateNew` is atomic, closing the TOCTOU/overwrite race (CWE-367): the loser of a creation race
  catches `IOException` and re-reads the winner's key instead of clobbering it. `info.json` metadata
  is written `0600` via `WriteFileRestricted` (overwrite-capable).
- On read, `EnsureOwnerOnlyPermissions` detects a group/other-accessible key file, warns, and tightens
  it back to `0600` (a pre-hardening or externally-created file may already have been exposed).

**Cleartext at rest (CWE-312/311).**
- `DeveloperKeyEncryptor` now encrypts its master key with **DPAPI** (`ProtectedData`, current-user
  scope) on Windows, marked with a `DNC\x50` header so legacy cleartext files are still readable.
  On non-Windows platforms DPAPI is unavailable, so the key stays cleartext **only if** the caller
  passes `allowUnencryptedKeyStore: true`; otherwise construction throws.
- `FolderBasedKeyEncryptor` throws unless a password is supplied or `allowUnencryptedKeys: true` is
  passed, and warns loudly when running passwordless.

**Tests.** `Sec3KeyStorageHardeningTests` asserts `0600`/`0700` modes and permission self-healing on
Unix, race-free concurrent construction, the opt-in throw paths, and (Windows-only) the DPAPI wrap
round-trip. CI now runs the suite on both `ubuntu-latest` and `windows-latest` so the platform-specific
paths are both exercised.

**Breaking changes.** Passwordless `FolderBasedKeyEncryptor` and (on Unix) `DeveloperKeyEncryptor` now
require an explicit opt-in flag; on Windows the developer key file format changes to DPAPI (pre-existing
cleartext dev files remain readable but new ones are protected).

## References

- CWE-312, CWE-276, CWE-311, CWE-367 (linked above).
- .NET API: `FileStreamOptions.UnixCreateMode`, `Directory.CreateDirectory(string, UnixFileMode)`, `System.Security.Cryptography.ProtectedData`.
