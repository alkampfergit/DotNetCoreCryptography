# SEC-4 — Unbounded Allocation from Untrusted Length Prefix

| | |
|---|---|
| **Finding ID** | SEC-4 |
| **Severity** | Medium |
| **CWE** | [CWE-789](https://cwe.mitre.org/data/definitions/789.html) (Memory Allocation with Excessive Size Value), [CWE-400](https://cwe.mitre.org/data/definitions/400.html) (Uncontrolled Resource Consumption) |
| **Component** | Envelope/hybrid decryption, RSA key deserialization |
| **Status** | Fixed |
| **Analysis date** | 2026-07-03 |
| **Fixed date** | 2026-07-04 |
| **Commit** | `9b0f088` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-5](SEC-5-key-deserialization-validation.md) (same deserialization routines lack semantic validation), [SEC-1](SEC-1-unauthenticated-encryption.md) (no integrity means these lengths cannot be trusted).

## Summary

Several decoders read a 32-bit length directly from untrusted input and pass it to
`BinaryReader.ReadBytes(length)`, which **allocates `new byte[length]` up front** before
reading. A tiny malicious input can therefore force a multi-gigabyte allocation, causing an
`OutOfMemoryException` or large-object-heap pressure — a denial-of-service.

## Resolution

Fixed on 2026-07-04.

- `SecureEncryptor.Decrypt` and `AsymmetricSecureEncryptor.Decrypt` validate wrapped-key
  lengths before allocation through `CryptoFormat.ValidateWrappedKeyLength`.
- `AsymmetricEncryptionUtils.DeserializeToRsa` now reads RSA components through a bounded
  helper that rejects negative, zero, oversized, and truncated lengths with
  `CryptographicException` before allocating component buffers.
- Regression tests cover `int.MaxValue`, negative, and truncated length prefixes for RSA key
  blobs, plus invalid v1/v2 wrapped-key lengths for both envelope decrypt paths.

## Affected code

### Envelope — `SecureEncryptor.Decrypt`

`src/DotNetCoreCryptographyCore/SecureEncryptor.cs`

```csharp
var length = bw.ReadInt32();          // attacker-controlled
var encryptedKey = bw.ReadBytes(length);   // pre-allocates new byte[length]
```

### Hybrid — `AsymmetricSecureEncryptor.Decrypt`

`src/DotNetCoreCryptographyCore/AsymmetricSecureEncryptor.cs`

```csharp
var length = bw.ReadInt32();
var encryptedKey = bw.ReadBytes(length);
```

### RSA key parsing — `AsymmetricEncryptionUtils.DeserializeToRsa`

`src/DotNetCoreCryptographyCore/AsymmetricEncryptionUtils.cs` — every component length is a
raw `ReadInt32` fed to `ReadBytes`:

```csharp
var exponentLength = br.ReadInt32();
pp.Exponent = br.ReadBytes(exponentLength);
var modulusLength = br.ReadInt32();
pp.Modulus = br.ReadBytes(modulusLength);
// ... D, DP, DQ, P, Q, InverseQ, each the same pattern
```

## Root cause

`BinaryReader.ReadBytes(count)` is documented to allocate a buffer of `count` bytes before
reading (it returns a shorter array only if EOF is hit *after* allocation). The code performs
no bounds check between reading the length and allocating, and no integrity check protects the
length field ([SEC-1](SEC-1-unauthenticated-encryption.md)). For the only supported key types
the valid sizes are known and small (an RSA-4096 wrapped key is exactly 512 bytes), so any
large length is invalid by construction.

## Exploitation

**Preconditions:** the attacker can supply bytes to a decrypt entry point. These are public
APIs of a published library intended to consume stored/transported data, and
`SecureEncryptor.Decrypt` is also reachable via the `DecryptAsync(string)` extension method.

1. Craft a small input whose first 4 bytes are a large little-endian length, e.g.
   `FF FF FF 7F` = `0x7FFFFFFF` (~2.1 GB).
2. Call the decrypt API. `ReadBytes(0x7FFFFFFF)` attempts a ~2 GB allocation before any
   cryptographic operation runs.
3. The process throws `OutOfMemoryException` or suffers severe GC/LOH pressure. Repeated
   requests amplify this into a service-wide DoS. A **negative** length (`0x80000000`) instead
   throws `ArgumentOutOfRangeException`, i.e. an uncontrolled non-`CryptographicException`
   failure.

No confidentiality or integrity is lost directly — the impact is availability — hence Medium.

## Impact

Denial of service (memory exhaustion / GC pressure) from a small crafted input on any decrypt
path, plus poor failure typing (framework exceptions escaping a crypto API).

## Remediation

Validate every length against a tight, type-appropriate upper bound before allocating, and
translate failures to `CryptographicException`:

```csharp
int length = reader.ReadInt32();
const int MaxWrappedKeyBytes = 1024;             // RSA-4096 wrapped key = 512 bytes
if (length <= 0 || length > MaxWrappedKeyBytes)
    throw new CryptographicException("Invalid wrapped-key length.");
byte[] wrapped = reader.ReadBytes(length);
if (wrapped.Length != length)
    throw new CryptographicException("Truncated input.");
```

For `DeserializeToRsa`, bound each component to the known RSA-4096 sizes (modulus 512, primes
256, CRT values 256, exponent ≤ 8) and verify `Modulus.Length == 512` (see
[SEC-5](SEC-5-key-deserialization-validation.md)). Prefer replacing the hand-rolled format
entirely with `RSA.ImportSubjectPublicKeyInfo` / `ImportPkcs8PrivateKey`, which validate
structure for you.

## Verification / tests to add

- Feed a blob with a `0x7FFFFFFF` length prefix and assert a fast `CryptographicException`
  (not `OutOfMemoryException`, not `ArgumentOutOfRangeException`) with no large allocation.
- Feed a negative length and a truncated body; assert `CryptographicException`.

Implemented in:

- `src/DotNetCoreCryptography.Tests/Core/AsymmetricEncryptionUtilsTests.cs`
- `src/DotNetCoreCryptography.Tests/Core/EnvelopeTamperTests.cs`

Verification command:

```shell
dotnet test src/DotNetCoreCryptography.Tests/DotNetCoreCryptography.Tests.csproj --filter "FullyQualifiedName~AsymmetricEncryptionUtilsTests|FullyQualifiedName~EnvelopeTamperTests"
```

## References

- CWE-789, CWE-400 (linked above).
- .NET API: `System.IO.BinaryReader.ReadBytes`, `RSA.ImportPkcs8PrivateKey`.
