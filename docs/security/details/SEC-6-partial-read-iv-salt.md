# SEC-6 — Partial Read of IV / Salt (Silent Key-Material Corruption)

| | |
|---|---|
| **Finding ID** | SEC-6 |
| **Severity** | Medium |
| **CWE** | [CWE-241](https://cwe.mitre.org/data/definitions/241.html) (Improper Handling of Unexpected Data), CWE-252 (Unchecked Return Value) |
| **Component** | `AesEncryptionKey`, `StaticEncryptor` |
| **Status** | ✅ **Fixed** (commit `d57a745`) |
| **Analysis date** | 2026-07-03 |
| **Commit** | `9b0f088` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-4](SEC-4-unbounded-allocation.md) (also untrusted-input parsing on the decrypt path).

## Summary

The IV (in `AesEncryptionKey`) and the password salt (in `StaticEncryptor`) were read with
`Stream.Read(buffer, 0, count)` while **ignoring the return value**. `Stream.Read` is
permitted to return fewer bytes than requested, so on certain stream types the IV/salt could
be left partially zero-filled and the stream misaligned, producing silent corruption or a
confusing downstream error. This has been **fixed** by switching to `ReadExactly` /
`ReadExactlyAsync`.

## Affected code (before fix)

`src/DotNetCoreCryptographyCore/AesEncryptionKey.cs` — `CreateDecryptor`:

```csharp
var newIV = new byte[newKey.IV.Length];
encryptedStream.Read(newIV, 0, newIV.Length);   // return value ignored
newKey.IV = newIV;
```

`src/DotNetCoreCryptographyCore/StaticEncryptor.cs` — `AesDecryptWithPasswordAsync` and
`AesDecryptWithPassword`:

```csharp
var salt = new byte[16];
encryptedStream.Read(salt, 0, salt.Length);     // return value ignored (sync + async)
```

## Root cause

`Stream.Read` returns the number of bytes actually read, which may be fewer than requested
"even if the end of the stream has not been reached" (per the .NET documentation). This is a
real behaviour for `NetworkStream`, `DeflateStream`/`GZipStream`, `CryptoStream`, and pipe-
backed `FileStream` — and the .NET 6 breaking change made partial reads more common. The code
assumed the buffer was always filled, which only holds for `MemoryStream` (which the tests
exclusively use — so the defect was never exercised).

On a short read:
- the trailing IV/salt bytes remain zero;
- the stream is left positioned mid-IV/salt;
- CBC decryption then proceeds with a wrong/partial IV, and because the remaining data is no
  longer block-aligned, `CryptoStream` typically throws a `CryptographicException` far from
  the root cause. On a zero-length read (truncated/empty input) the all-zero IV/salt is used
  and decryption can silently yield empty output rather than failing loudly.

The net10 retarget surfaced this as analyzer warning **CA2022** ("Avoid inexact read").

## Impact (before fix)

Reliability/correctness defect on the library's public decrypt paths for non-`MemoryStream`
inputs: silent bad output on truncated input, or confusing errors on short reads. Not a break
of the cryptography itself, hence Medium.

## Resolution

Fixed in commit `d57a745` by using the fill-or-throw APIs:

`AesEncryptionKey.CreateDecryptor`:

```csharp
var newIV = new byte[newKey.IV.Length];
encryptedStream.ReadExactly(newIV);             // throws EndOfStreamException on truncation
newKey.IV = newIV;
```

`StaticEncryptor` (async / sync):

```csharp
await encryptedStream.ReadExactlyAsync(salt).ConfigureAwait(false);   // async path
encryptedStream.ReadExactly(salt);                                     // sync path
```

`ReadExactly`/`ReadExactlyAsync` (available since .NET 7) either fill the buffer completely or
throw `EndOfStreamException`, converting the previous silent misbehaviour into a clean,
deterministic failure. This also cleared the CA2022 warnings from the net10 build.

## Verification / tests to add

- Decrypt from a stream that returns the IV/salt in fragments (a wrapper stream that returns
  1 byte per `Read`) and assert correct decryption.
- Decrypt from a truncated stream (fewer than 16 bytes) and assert `EndOfStreamException`
  rather than empty output or a padding error.

## References

- CWE-241, CWE-252 (linked above).
- .NET analyzer rule **CA2022** ("Avoid inexact read with `Stream.Read`").
- .NET API: `Stream.ReadExactly`, `Stream.ReadExactlyAsync`.
