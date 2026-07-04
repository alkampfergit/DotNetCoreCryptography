# SEC-8 — Key Material Not Zeroized in Memory

| | |
|---|---|
| **Finding ID** | SEC-8 |
| **Severity** | Low (defense-in-depth) |
| **CWE** | [CWE-316](https://cwe.mitre.org/data/definitions/316.html) (Cleartext Storage of Sensitive Information in Memory), CWE-226 (Sensitive Information Uncleared Before Release) |
| **Component** | `AsymmetricSecureEncryptor`, `AsymmetricEncryptionUtils`, `EncryptionUtils`, `AzureKeyVaultStoreKeyEncryptor` |
| **Status** | Fixed (best-effort) |
| **Analysis date** | 2026-07-03 |
| **Fixed date** | 2026-07-04 |
| **Commit** | `9b0f088` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-7](SEC-7-non-constant-time-comparison.md).

## Summary

Transient buffers holding plaintext key material — decrypted data-encryption keys, RSA
private parameters, PBKDF2-derived keys — are abandoned to the garbage collector without being
overwritten. Until the GC reclaims and reuses the memory, the secrets remain readable in the
process heap, and may reach crash dumps or the page/swap file.

## Affected code (representative)

`src/DotNetCoreCryptographyCore/AsymmetricSecureEncryptor.cs`

```csharp
// Decrypt: raw AES key + IV + mode, never cleared
var serializedKey = asymmetricKey.Decrypt(encryptedKey);
using var originalKey = EncryptionKey.CreateFromSerializedVersion(serializedKey);
// ... serializedKey lingers on the heap

// Encrypt: same unwiped copy created inline (no variable to clear)
var encrypted = asymmetricKey.Encrypt(key.Serialize());
```

`src/DotNetCoreCryptographyCore/AsymmetricEncryptionUtils.cs` — `Serialize`/`DeserializeToRsa`
copy `D`, `P`, `Q`, `DP`, `DQ`, `InverseQ` (from `ExportParameters(true)`) into a
`MemoryStream` and a `ToArray()` duplicate; none are cleared. `MemoryStream.Dispose` does not
zero its backing buffer.

`src/DotNetCoreCryptographyCore/EncryptionUtils.cs` — the PBKDF2-derived key/IV and the
`ArraySegment.ToArray()` intermediates in `Serialize`/`DeserializeToAes`.

`src/DotNetCoreCryptography.Azure/AzureKeyVaultStoreKeyEncryptor.cs` — `result.Plaintext`
(the unwrapped DEK) and the `key.Serialize()` buffer.

## Root cause

.NET does not zero managed memory on garbage collection, and a compacting GC may copy the
buffer elsewhere before reclaiming it. The framework itself scrubs buffers it owns
(`SymmetricAlgorithm.Dispose` zeroes its internal `KeyValue`/`IVValue`), but these stray
application-level arrays are never wiped, so they survive until the memory is reused.

## Exploitation

**Preconditions:** an independent memory-disclosure primitive — a heap/crash dump, a core
file, hibernation image, or swap access. This is why the finding is **Low**: it is not
directly exploitable on its own.

Given such access, an analyst scanning the dump can recover data-encryption keys and RSA
private components that were live in the process, even after the corresponding
`EncryptionKey`/`RSA` objects were disposed — because the plaintext copies in these arrays
were never cleared.

## Impact

Increased residence time of plaintext key material in process memory, widening the window in
which a memory-disclosure event exposes keys. Marginal on its own; relevant hygiene for a
library whose sole purpose is key handling.

## Remediation

Wipe transient key buffers in a `try/finally` once they are no longer needed:

```csharp
using System.Security.Cryptography;

byte[] serializedKey = asymmetricKey.Decrypt(encryptedKey);
try
{
    using var originalKey = EncryptionKey.CreateFromSerializedVersion(serializedKey);
    // ... use originalKey ...
}
finally
{
    CryptographicOperations.ZeroMemory(serializedKey);
}
```

Apply the same pattern to:
- the `key.Serialize()` result before/after wrapping,
- the PBKDF2-derived key/IV in `EncryptionUtils` (safe: `CreateEncryptor(key, iv)` copies them),
- Azure `result.Plaintext` after `CreateFromSerializedVersion` copies it out,
- RSA parameter arrays after use (write into a rented/pinned buffer you can wipe instead of a
  `MemoryStream`).

`CryptographicOperations.ZeroMemory` is not elided by the JIT (unlike a hand-written loop),
which is why it is the correct tool. Note this remains best-effort under a compacting GC; the
robust long-term direction is to minimise the number of managed copies of key material.

## Verification

Difficult to unit-test deterministically; verify by code review that every path producing a
plaintext key buffer has a corresponding `ZeroMemory` in a `finally`.

## Resolution (2026-07-04)

Transient plaintext DEK buffers are now wiped with `CryptographicOperations.ZeroMemory` in a
`finally` on the paths that produce them:

- `FolderBasedKeyEncryptor.EncryptAsync` / `GenerateNewKey` — the `key.Serialize()` buffer
  (already in place from the SEC-1/SEC-3 work).
- `CryptoFormat.CreateKeyWrapAes` — the raw key material loaded for AES-KWP (already in place).
- `AsymmetricSecureEncryptor.Encrypt` — the serialized key before wrapping; `Decrypt` — the
  unwrapped serialized key after `CreateFromSerializedVersion` copies it out (both branches).
- `AzureKeyVaultStoreKeyEncryptor.EncryptAsync` — the serialized key; `DecryptAsync` — the
  `result.Plaintext` DEK returned by Key Vault.
- `AesEncryptionKey.Equals` — the key/IV getter copies (shared with the
  [SEC-7](SEC-7-non-constant-time-comparison.md) fix).

**Residual (accepted):** the RSA parameter arrays produced by `ExportParameters(true)` and the
`MemoryStream`/`ToArray()` intermediates in `AsymmetricEncryptionUtils.Serialize` /
`DeserializeToRsa` are not individually scrubbed — `MemoryStream` does not expose its backing
buffer for wiping. As the finding notes, zeroization is inherently best-effort under a
compacting GC; eliminating these copies would require a pinned/rented-buffer rewrite of the
RSA format, disproportionate to a Low finding. Left as a known limitation.

## References

- CWE-316, CWE-226 (linked above).
- Microsoft Learn: `SymmetricAlgorithm.Clear` remarks (GC does not zero collected objects).
- .NET API: `System.Security.Cryptography.CryptographicOperations.ZeroMemory`.
