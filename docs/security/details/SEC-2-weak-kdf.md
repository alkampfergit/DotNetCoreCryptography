# SEC-2 — Weak Password-Based Key Derivation

| | |
|---|---|
| **Finding ID** | SEC-2 |
| **Severity** | High |
| **CWE** | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) (Use of Password Hash With Insufficient Computational Effort), [CWE-326](https://cwe.mitre.org/data/definitions/326.html) (Inadequate Encryption Strength) |
| **Component** | Password-based key derivation for keys at rest |
| **Status** | Open (algorithm preserved for compatibility; flagged in source with a `WARNING` comment) |
| **Analysis date** | 2026-07-03 |
| **Commit** | `9b0f088` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-3](SEC-3-insecure-key-storage.md) (the key files this KDF protects are also world-readable), [SEC-1](SEC-1-unauthenticated-encryption.md).

## Summary

Password-based protection derives its AES key and IV using **PBKDF2-HMAC-SHA1 with 1000
iterations**. Both the 32-byte key and the 16-byte IV are taken from a single PBKDF2 output
stream. This is roughly three orders of magnitude below current guidance and makes offline
password cracking cheap. This KDF is the entire at-rest protection of
`FolderBasedKeyEncryptor` when a password is configured.

## Affected code

`src/DotNetCoreCryptographyCore/EncryptionUtils.cs`

```csharp
// WARNING: PBKDF2-HMAC-SHA1 at 1000 iterations is retained here only for
// backward compatibility with data already encrypted by this library. It is
// far below current guidance (OWASP recommends >=600,000 iterations with
// SHA-256) and should be replaced behind a format-version bump. See the
// security audit "weak KDF" finding.
private const int LegacyPbkdf2Iterations = 1000;

private static (byte[] Key, byte[] Iv) DeriveKeyAndIv(string password, byte[] salt)
{
    // Derive key (32 bytes) followed by IV (16 bytes) from a single PBKDF2
    // stream, matching the previous sequential GetBytes(32)/GetBytes(16) layout
    // so existing ciphertext remains decryptable.
    var derived = Rfc2898DeriveBytes.Pbkdf2(
        password, salt, LegacyPbkdf2Iterations, HashAlgorithmName.SHA1, 48);
    return (derived[..32], derived[32..]);
}
```

Call chain to the sensitive asset:

```
FolderBasedKeyEncryptor.Encrypt/Decrypt (Concrete/FolderBasedKeyEncryptor.cs:57,69)
  -> StaticEncryptor.AesEncryptWithPassword / AesDecryptWithPassword (StaticEncryptor.cs)
    -> Aes.GetEncryptorFromPassword / GetDecryptorFromPassword (EncryptionUtils.cs)
      -> DeriveKeyAndIv  (PBKDF2-SHA1, 1000 iterations)
```

The salt is a random 16 bytes, but it is written **in cleartext** as the first 16 bytes of
each encrypted key file (`StaticEncryptor.AesEncryptWithPassword` prepends it), so it does
not slow an attacker who already has the file — it only prevents cross-file rainbow tables.

## Root cause

Two problems compound:

1. **Iteration count far too low.** 1000 iterations of PBKDF2 was a 2005-era default. OWASP's
   current Password Storage Cheat Sheet recommends **≥ 600,000 iterations for PBKDF2-HMAC-
   SHA256** (≥ 1,300,000 for SHA-1). At 1000 iterations, each password guess costs about 1000
   HMAC operations — trivially parallelizable on GPUs/ASICs.
2. **Legacy hash (SHA-1).** The parameterless-hash `Rfc2898DeriveBytes` behavior defaulted to
   HMAC-SHA1; that default is preserved here.

Deriving the IV from the same KDF stream is a secondary weakness: with a fixed password+salt
the IV is deterministic, so re-encrypting the same key file reproduces the same IV. Combined
with the unauthenticated CBC of [SEC-1](SEC-1-unauthenticated-encryption.md), this reduces
IV hygiene, though the dominant risk here is the cracking cost.

## Exploitation

**Preconditions:** the attacker obtains a copy of the key-material folder (backup, snapshot,
misconfigured share, or via [SEC-3](SEC-3-insecure-key-storage.md) on a shared host).

1. Read any `{n}.key` file; the first 16 bytes are the cleartext salt.
2. Run an offline dictionary / brute-force attack: for each candidate password, compute
   `PBKDF2-SHA1(candidate, salt, 1000, 48)`, take the first 32 bytes as the AES key, attempt
   to decrypt the file, and check whether the result deserializes to a valid key
   (`KeyType.Aes256` marker at byte 0).
3. On success, the attacker holds the master key-encryption key and can decrypt **every
   wrapped data key**, and therefore all data the library protected.

Because 1000 iterations is so cheap, a commodity GPU tests billions of PBKDF2-SHA1 candidates
per hour, putting typical human-chosen passwords well within reach.

## Impact

Full compromise of confidentiality for all data protected by a `FolderBasedKeyEncryptor`
instance, contingent only on obtaining the key folder and cracking one password.

## Remediation

Adopt modern parameters behind a format-version bump (so old files remain readable):

```csharp
// New format: derive ONLY the key; use a random per-message IV; store params in the header.
const int Iterations = 600_000;                       // review against current OWASP guidance
byte[] key = Rfc2898DeriveBytes.Pbkdf2(
    password, salt, Iterations, HashAlgorithmName.SHA256, 32);
byte[] iv  = RandomNumberGenerator.GetBytes(12);       // if moving to AES-GCM (SEC-1)
```

Guidance:
- Use **PBKDF2-HMAC-SHA256 with ≥ 600,000 iterations**, or a memory-hard KDF (Argon2id, e.g.
  via `Konscious.Security.Cryptography` or `libsodium`) for stronger resistance.
- **Do not** derive the IV/nonce from the password KDF; generate it randomly per message.
- Store the KDF algorithm, iteration count, and salt in the file header so parameters can be
  raised over time without breaking existing data.
- Combine with the authenticated format from [SEC-1](SEC-1-unauthenticated-encryption.md).

## Note on current status

When the obsolete `Rfc2898DeriveBytes` **constructor** was replaced with the static `Pbkdf2`
one-shot (to clear the SYSLIB0060 build warning from the net10 retarget), the algorithm and
parameters were **intentionally preserved** (SHA-1 / 1000 iterations / key‖IV layout) so that
data already encrypted by the library continues to decrypt. The weakness is therefore
unchanged in strength and is explicitly flagged in the source. Strengthening it is a breaking
on-disk-format change and should be delivered with the SEC-1 format-version work.

## References

- CWE-916, CWE-326 (linked above).
- OWASP Password Storage Cheat Sheet (PBKDF2 iteration guidance).
- NIST SP 800-132 (PBKDF2); RFC 9106 (Argon2).
- .NET API: `Rfc2898DeriveBytes.Pbkdf2`, diagnostic `SYSLIB0060`.
