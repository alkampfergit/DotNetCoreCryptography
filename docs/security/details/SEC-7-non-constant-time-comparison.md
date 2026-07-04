# SEC-7 — Non-Constant-Time Comparison of Secret Key Material

| | |
|---|---|
| **Finding ID** | SEC-7 |
| **Severity** | Low (defense-in-depth) |
| **CWE** | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) (Observable Timing Discrepancy) |
| **Component** | `AesEncryptionKey.Equals`, `AsymmetricEncryptionUtils.KeyEqual` |
| **Status** | Fixed |
| **Analysis date** | 2026-07-03 |
| **Fixed date** | 2026-07-04 |
| **Commit** | `9b0f088` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-8](SEC-8-key-material-not-zeroized.md) (the same getters allocate un-wiped key copies).

## Summary

Secret key material is compared byte-by-byte with LINQ `Enumerable.SequenceEqual`, which
short-circuits on the first differing byte and is therefore **not constant-time**. In a
context where an attacker controls one operand and can measure comparison time, this leaks the
length of the matching prefix.

## Affected code

`src/DotNetCoreCryptographyCore/AesEncryptionKey.cs`

```csharp
public override bool Equals(object obj)
{
    return obj is AesEncryptionKey otherKey
        && otherKey._key.Key.SequenceEqual(_key.Key)   // early-exit, non-constant-time
        && otherKey._key.IV.SequenceEqual(_key.IV)
        && otherKey._key.Mode == _key.Mode;
}
```

`src/DotNetCoreCryptographyCore/AsymmetricEncryptionUtils.cs`

```csharp
public static bool KeyEqual(this RSAParameters p1, RSAParameters p2)
{
    return p1.D.SequenceEqual(p2.D)
        && p1.DP.SequenceEqual(p2.DP)
        // ... etc, all early-exit
}
```

Note also that each `_key.Key` / `_key.IV` getter access **allocates a fresh copy** of the
secret (see [SEC-8](SEC-8-key-material-not-zeroized.md)).

## Root cause

`SequenceEqual` is a general-purpose equality helper optimised to return as soon as a
difference is found. Cryptographic comparisons of secrets must instead take time independent
of where the first difference occurs, to avoid a timing side channel.

## Exploitation

This is reported as **defense-in-depth** because, as written, the comparisons are not reached
from any security decision:

- `AesEncryptionKey.Equals` and `RsaEncryptionKey.IsEqualTo` (which calls `KeyEqual`) are
  invoked only from the test suite in the current codebase.
- For RSA specifically, a private exponent `D` is mathematically determined by `P`, `Q`, and
  `E`, so an attacker cannot enumerate candidate keys with chosen successive prefixes; and each
  `KeyEqual` call performs two `ExportParameters(true)` operations whose timing noise dwarfs
  the memcmp early-exit delta.

If a future change routes attacker-controlled input into these comparisons as an
authentication/authorization check (e.g. "does this submitted key match the stored key?"), the
timing channel would become exploitable to recover the secret prefix-by-prefix.

## Impact

Currently negligible (not reachable in a security decision). The concern is latent: a public
cryptographic library should not ship timing-unsafe secret comparisons that a consumer might
unknowingly place on an attacker-observable path.

## Remediation

Use the constant-time comparison helper:

```csharp
using System.Security.Cryptography;

// AES
bool keysEqual = CryptographicOperations.FixedTimeEquals(otherKey._key.Key, _key.Key);

// RSA component (guard nulls for public-only parameters)
static bool Eq(byte[]? a, byte[]? b) =>
    (a is null && b is null) ||
    (a is not null && b is not null && CryptographicOperations.FixedTimeEquals(a, b));
```

`CryptographicOperations.FixedTimeEquals(ReadOnlySpan<byte>, ReadOnlySpan<byte>)` runs in time
independent of the contents and also removes the `System.Linq` dependency. Pair with
[SEC-8](SEC-8-key-material-not-zeroized.md) to wipe the temporary copies afterwards, and
reconsider whether public value-equality over secret keys should be exposed at all.

## Resolution (2026-07-04)

- `AesEncryptionKey.Equals` now compares key and IV with
  `CryptographicOperations.FixedTimeEquals` and wipes the transient getter copies in a
  `finally` (also addressing [SEC-8](SEC-8-key-material-not-zeroized.md)).
- `AsymmetricEncryptionUtils.KeyEqual` compares every `RSAParameters` component with
  `FixedTimeEquals` via a small `FixedTimeEqual` helper; a null component (public-only
  parameters) converts to an empty span, so a null/non-null mismatch fails the length check
  without a timing signal.
- The `System.Linq` dependency was removed from both files. Existing tests
  (`Can_serialize_and_deserialize_key`, `Export_only_public_key`) exercise both the
  equal-key and public-only comparison paths.

## References

- CWE-208 (linked above).
- .NET API: `System.Security.Cryptography.CryptographicOperations.FixedTimeEquals`.
