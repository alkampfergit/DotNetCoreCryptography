# SEC-1 — Unauthenticated Encryption (Missing Integrity)

| | |
|---|---|
| **Finding ID** | SEC-1 |
| **Severity** | Critical |
| **CWE** | [CWE-353](https://cwe.mitre.org/data/definitions/353.html) (Missing Support for Integrity Check), [CWE-649](https://cwe.mitre.org/data/definitions/649.html) (Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking) |
| **Component** | Symmetric core, envelope encryption, hybrid encryption, key wrapping |
| **Status** | ✅ Fixed (2026-07-03, branch `feature/modernization` — see [Resolution](#resolution)) |
| **Analysis date** | 2026-07-03 |
| **Commit** | `9b0f088` (analysis) |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-5](SEC-5-key-deserialization-validation.md) (mode downgrade rides on this), [SEC-2](SEC-2-weak-kdf.md), [SEC-4](SEC-4-unbounded-allocation.md).

## Summary

Every symmetric encryption path in the library uses **AES in CBC mode with PKCS7 padding**
and writes the IV in the clear, with **no message authentication code and no AEAD tag
anywhere**. The ciphertext is therefore unauthenticated: its integrity and authenticity are
not verified on decryption. This applies not only to user payloads but also to the
**wrapped data-encryption keys**, because the key-wrapping code reuses the same CBC path.

A repository-wide search of `src/` for `HMAC`, `AesGcm`, or any authentication primitive
returns no matches.

## Affected code

### 1. The symmetric primitive — `AesEncryptionKey`

`src/DotNetCoreCryptographyCore/AesEncryptionKey.cs`

```csharp
public override ICryptoTransform CreateEncryptor(Stream destinationStream)
{
    using var newKey = Aes.Create();          // CipherMode.CBC, PaddingMode.PKCS7 (defaults)
    newKey.Key = _key.Key;
    newKey.Mode = _key.Mode;
    newKey.IV  = EncryptionUtils.GenerateRandomByteArray(newKey.IV.Length);
    destinationStream.Write(newKey.IV, 0, newKey.IV.Length);   // IV written in cleartext
    return newKey.CreateEncryptor();
}

public override ICryptoTransform CreateDecryptor(Stream encryptedStream)
{
    using var newKey = Aes.Create();
    newKey.Key = _key.Key;
    newKey.Mode = _key.Mode;
    var newIV = new byte[newKey.IV.Length];
    encryptedStream.ReadExactly(newIV);        // reads IV back; no integrity check
    newKey.IV = newIV;
    return newKey.CreateDecryptor();
}
```

`Aes.Create()` returns an implementation whose defaults are `CipherMode.CBC` and
`PaddingMode.PKCS7` (confirmed in the .NET documentation). There is no tag, no MAC, and no
verification step.

### 2. The envelope format — `SecureEncryptor`

`src/DotNetCoreCryptographyCore/SecureEncryptor.cs` produces:

```
[ int32: wrapped-key length ][ wrapped key ][ 16-byte IV ][ AES-CBC/PKCS7 ciphertext ]
```

None of these fields is integrity-protected — not the length header, not the wrapped key,
not the IV, not the payload.

### 3. The hybrid format — `AsymmetricSecureEncryptor`

`src/DotNetCoreCryptographyCore/AsymmetricSecureEncryptor.cs` uses the same shape, with the
data key wrapped by RSA-OAEP-SHA512. The RSA wrap protects the key's confidentiality but
adds no integrity over the IV or ciphertext body, and nothing binds the header to the
payload.

### 4. Key wrapping reuses the same path

`src/DotNetCoreCryptographyCore/Concrete/FolderBasedKeyEncryptor.cs:107` and
`Concrete/DeveloperKeyEncryptor.cs:44` wrap the serialized data key with
`StaticEncryptor.EncryptAsync`, i.e. plain AES-CBC. **The wrapped key blobs are therefore
malleable too.**

## Root cause

The design predates the general availability of authenticated encryption in .NET and treats
"encryption" as equivalent to "confidentiality". CBC provides confidentiality only. Without
an integrity mechanism (encrypt-then-MAC, or an AEAD such as AES-GCM), a decryptor cannot
distinguish authentic ciphertext from ciphertext an attacker has altered.

## Exploitation

The attacker model is an active attacker with **write access to the ciphertext** (data at
rest in shared storage, a message in transit, a blob in a queue, etc.). The attacker does
**not** need any key.

### A. Bit-flipping the first block (CBC malleability)

In CBC decryption, `P1 = D(C1) XOR IV`. The IV is stored in cleartext at the start of the
stream. Flipping bit *i* of the stored IV flips bit *i* of plaintext block `P1`,
deterministically and with no detection. If `P1` contains, say, a JSON header
`{"admin":false ...}` or an amount field, the attacker can flip targeted bits to alter it.
The same technique against `C1` corrupts `P2` in a controlled way.

### B. Padding-oracle plaintext recovery

If the application exposes any observable difference between a PKCS7 padding failure
(`CryptographicException` from `CryptoStream`) and other outcomes — a distinct error
response, a different latency, a log line — the classic CBC padding-oracle attack recovers
plaintext one byte at a time without the key. This is the canonical break of unauthenticated
CBC (Vaudenay).

### C. Undetected truncation

An attacker can drop trailing ciphertext blocks; as long as the remaining stream still
decodes to valid padding, decryption succeeds on a truncated message.

### D. Tampering with wrapped keys

Because the wrapped data key is itself CBC without integrity, an attacker who can modify the
key blob can flip bits in the wrapped key, causing the victim to decrypt with attacker-
perturbed key material — at minimum a corruption/denial primitive, and a building block for
more advanced attacks in combination with [SEC-5](SEC-5-key-deserialization-validation.md)
(mode downgrade to ECB).

## Impact

- Loss of **integrity** and **authenticity** of all encrypted data and all wrapped keys.
- Potential loss of **confidentiality** via padding oracle (CWE-649).
- The library is published to NuGet under the name `SecureEncryptor`, so consumers reasonably
  assume tamper protection they do not receive.

## Remediation

Move to authenticated encryption and bind the whole envelope.

### Payloads — AES-GCM

```csharp
// 12-byte nonce (unique per message), 16-byte tag.
using var gcm = new AesGcm(key, tagSizeInBytes: 16);   // explicit tag size required since .NET 8
var nonce = RandomNumberGenerator.GetBytes(12);
var tag   = new byte[16];
var ciphertext = new byte[plaintext.Length];
gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: header);
// Emit: [version][header][nonce][tag][ciphertext]
```

Pass the envelope header (format version, wrapped-key length, key id) as `associatedData` so
the header is authenticated together with the payload. For large streams, use a chunked
AES-GCM construction with a per-chunk nonce derived from a counter, and authenticate chunk
ordering/finality to prevent truncation and reordering.

### Key wrapping — AES-KWP (RFC 5649), new in .NET 10

```csharp
byte[] wrapped   = kek.EncryptKeyWrapPadded(dataKeyBytes);   // integrity built in
byte[] unwrapped = kek.DecryptKeyWrapPadded(wrapped);        // throws on tamper
```

`AesGcm` is also acceptable for wrapping. Either way, unwrap must **fail closed** on any
modification.

### Versioning

Introduce a leading format-version byte so existing v1 (CBC) data can still be read while all
newly written data is authenticated. This also enables fixing [SEC-2](SEC-2-weak-kdf.md) and
[SEC-5](SEC-5-key-deserialization-validation.md) in the same format revision.

## Verification / tests to add

- Encrypt, flip one bit in each region (header, wrapped key, nonce/IV, ciphertext, tag), and
  assert decryption throws `CryptographicException`.
- Truncate the ciphertext by one block and assert decryption fails.
- Confirm decryption failures are reported uniformly (no padding-vs-other distinction leaked
  to callers).

## Resolution

Implemented on 2026-07-03 (branch `feature/modernization`) as the **v2 authenticated,
versioned format**. All newly written data is authenticated; all v1 data remains readable
(formats are distinguished by the leading magic `44 4E 43 02` — "DNC" + version — which
cannot collide with plausible v1 field values).

### What changed

- **New default key — `AesGcmEncryptionKey`** (`KeyType.Aes256Gcm = 2`), returned by
  `EncryptionKey.CreateDefault()`. Payloads use AES-256-GCM in a chunked STREAM
  construction: 7-byte random nonce prefix, per-chunk nonce
  `prefix || 32-bit BE counter || final-flag byte`, 16-byte tag per 64 KiB chunk, final
  chunk marked in both the header and the nonce. Bit-flips, truncation, chunk reordering
  and trailing data all fail closed. Key serialization is `[0x02][32 raw key bytes]` —
  no IV and **no mode byte** (removing the SEC-5 downgrade surface for new keys).
- **`EncryptionKey` API**: new stream-based `Encrypt/Decrypt(Async)` accepting optional
  associated data. The `ICryptoTransform`-based methods are `[Obsolete]` and only
  implemented by the legacy CBC key.
- **v2 envelope** (`SecureEncryptor`, `AsymmetricSecureEncryptor`):
  `[magic][int32 wrapped-key length][wrapped key][chunked GCM payload]`, with the whole
  header bound to the payload as associated data — swapping the wrapped key or altering
  the length field fails authentication. The length field is bounded (8 KiB) before
  allocation, closing this path of [SEC-4](SEC-4-unbounded-allocation.md).
- **Key wrapping** (`FolderBasedKeyEncryptor`, `DeveloperKeyEncryptor`): RFC 5649 AES-KWP
  via .NET 10 `Aes.EncryptKeyWrapPadded`/`DecryptKeyWrapPadded`; unwrap fails closed on
  any modification. Note that KWP is deterministic by design (it replaced the CBC wrap
  with random IV, so the former "same key wraps differently every time" behavior is gone).
- **Password format v2**: `[magic][16-byte salt][chunked GCM payload]` with
  PBKDF2-HMAC-SHA256 at 600,000 iterations ([SEC-2](SEC-2-weak-kdf.md) for newly written
  data). KDF parameters are implied by the format version byte rather than stored in the
  header, so they can be neither downgraded nor inflated (CPU-exhaustion) by tampering.
- **Legacy key deserialization hardened**: exact 50-byte length enforced, cipher mode
  whitelisted to CBC (ECB/CFB rejected; the test asserting ECB round-trip was inverted) —
  partial fix of [SEC-5](SEC-5-key-deserialization-validation.md).
- **Uniform failure**: every decryption failure in the new paths surfaces as
  `CryptographicException("Decryption failed.")` with no padding-vs-tag distinction.

### Verification

- `AesGcmEncryptionKeyTests` — round-trips at chunk boundaries (0, 1, 64Ki−1, 64Ki,
  64Ki+1, 3×64Ki+17), **every bit of the ciphertext flipped** → throws, truncation at
  **every length** → throws, chunk swap → throws, trailing data → throws, associated-data
  binding, wrong-key rejection.
- `EnvelopeTamperTests` — every bit of the symmetric envelope flipped → throws; truncation
  at every length → throws; valid wrapped key grafted from another envelope → throws;
  asymmetric envelope bit-flips → throws; tampered password data never yields the original
  plaintext; wrong password → throws.
- `FolderBasedKeyValueStoreSpecificTests.Wrapped_key_blobs_are_tamper_evident` — every bit
  of a wrapped key blob flipped → unwrap throws.
- `V1CompatibilityTests` — fixtures generated with the pre-fix library (committed under
  `src/DotNetCoreCryptography.Tests/Core/Fixtures/v1`) still decrypt: static key stream,
  password data, folder-based and developer envelopes, wrapped-key blob, asymmetric
  envelope; and a legacy (CBC) key-encryption key wraps new blobs in v2/KWP.

### Residual notes

- v1 (CBC) data is still **readable** for migration; it stays unauthenticated by nature.
  Consumers should re-encrypt valuable data; a future major release should require an
  explicit opt-in for legacy decryption.
- [SEC-3](SEC-3-insecure-key-storage.md) (key file permissions) is unchanged by this fix.

## References

- CWE-353, CWE-649 (linked above).
- NIST SP 800-38D (GCM); RFC 5116 (AEAD); RFC 5649 (AES Key Wrap with Padding).
- Microsoft Learn: *Timing vulnerabilities with CBC-mode symmetric decryption using padding*.
- .NET API: `System.Security.Cryptography.AesGcm`, `Aes.EncryptKeyWrapPadded`.
