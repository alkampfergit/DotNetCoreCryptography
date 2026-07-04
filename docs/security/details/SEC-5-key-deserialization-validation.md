# SEC-5 — Missing Validation on Key Deserialization (Algorithm/Size Downgrade)

| | |
|---|---|
| **Finding ID** | SEC-5 |
| **Severity** | Medium |
| **CWE** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) (Improper Input Validation), [CWE-757](https://cwe.mitre.org/data/definitions/757.html) (Selection of Less-Secure Algorithm During Negotiation / 'Algorithm Downgrade'), [CWE-327](https://cwe.mitre.org/data/definitions/327.html) (Use of a Broken or Risky Cryptographic Algorithm) |
| **Component** | `EncryptionUtils` (AES key blob), `AsymmetricEncryptionUtils` (RSA key blob) |
| **Status** | Open |
| **Analysis date** | 2026-07-03 |
| **Commit** | `9b0f088` |

Parent report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).
Related: [SEC-1](SEC-1-unauthenticated-encryption.md) (unauthenticated wrapping makes downgrade reachable), [SEC-4](SEC-4-unbounded-allocation.md).

## Summary

The serialized-key parsers accept structurally malformed or downgraded key material:

- `DeserializeToAes` honours an attacker-supplied **cipher-mode byte verbatim**, so a blob
  marked `Mode = ECB` round-trips and yields **ECB encryption of user data**.
- The AES key length is derived from the blob length, so a short blob silently produces a
  **128-bit key still tagged `Aes256`**; `Serialize` stamps `Aes256` without checking
  `KeySize == 256`.
- `DeserializeToRsa` validates only the type byte and never verifies the key is actually
  **4096-bit**, even though `Serialize` enforces that on the way out.

## Affected code

`src/DotNetCoreCryptographyCore/EncryptionUtils.cs`

```csharp
public static byte[] Serialize(this Aes aes)
{
    // ... stamps KeyType.Aes256 regardless of aes.KeySize ...
    array[0] = (byte)KeyType.Aes256;
    // ...
    array[^1] = (byte)aes.Mode;         // mode persisted verbatim
    return array;
}

public static Aes DeserializeToAes(this byte[] serializedAes)
{
    if (serializedAes[0] != (byte)KeyType.Aes256)
        throw new CryptographicException("Serialized key is not AES");
    var aes = Aes.Create();
    var keyLength = serializedAes.Length - 16 - 1 - 1;      // derived from blob length
    aes.IV  = new ArraySegment<byte>(serializedAes, 1, 16).ToArray();
    aes.Key = new ArraySegment<byte>(serializedAes, 17, keyLength).ToArray();  // any length
    aes.Mode = (CipherMode)serializedAes[^1];               // ECB (2) accepted
    return aes;
}
```

`src/DotNetCoreCryptographyCore/AsymmetricEncryptionUtils.cs`

```csharp
public static byte[] Serialize(this RSA rsa, bool includePrivatePart)
{
    if (rsa.KeySize != 4096)
        throw new ArgumentException("Rsa key size should be 4096 bits");   // enforced on write
    // ...
}

public static RSA DeserializeToRsa(this byte[] serializedRsaKey, out bool hasPrivateKey)
{
    if (serializedRsaKey[0] != (byte)AsymmetricKeyType.Rsa4096)
        throw new CryptographicException("Serialized key is not RSA 4096 bits");
    // ... reads Modulus etc. but NEVER checks Modulus.Length == 512 ...
    return RSA.Create(pp);              // accepts a weak/short key tagged Rsa4096
}
```

The library's own test suite encodes the ECB behaviour as a requirement:
`src/DotNetCoreCryptography.Tests/Core/EncryptionUtilsTests.cs`

```csharp
[Theory]
[InlineData(CipherMode.CBC)]
[InlineData(CipherMode.ECB)]   // asserts ECB round-trips
[InlineData(CipherMode.CFB)]
public void SerializationMaintainModeOfOperation(CipherMode mode) { ... }
```

## Root cause

The parsers trust the serialized form to be well-formed and self-consistent, performing only
a single type-marker check. There is no enforcement that the declared type matches the actual
key size, and the cipher mode is treated as free-form data rather than a constrained,
security-relevant parameter. ECB is a broken mode for general data (identical plaintext blocks
produce identical ciphertext blocks — CWE-327).

## Exploitation

Key blobs are normally wrapped, but that wrapping is unauthenticated CBC
([SEC-1](SEC-1-unauthenticated-encryption.md)), so an attacker who can tamper with stored key
material is in scope.

1. **Mode downgrade to ECB.** An attacker who can influence the decrypted key blob (e.g. by
   manipulating the malleable wrapped-key ciphertext, or by writing to a world-readable key
   file per [SEC-3](SEC-3-insecure-key-storage.md)) flips the trailing mode byte to `2` (ECB).
   Subsequent `CreateEncryptor` faithfully encrypts user data in ECB, leaking plaintext block
   structure.
2. **Key-size confusion.** A blob whose key segment is 16 bytes deserializes to a 128-bit AES
   key while still advertising `Aes256`, or an RSA blob with a 1024-bit modulus is used as a
   "4096-bit" key — a silent strength downgrade that violates the type's security claim.
3. **Poor failure modes.** An empty array throws `IndexOutOfRangeException` at
   `serializedAes[0]`; a short array throws `ArgumentException` from `ArraySegment` — neither
   is the intended `CryptographicException` (see [SEC-9](SEC-9-error-information-disclosure.md)).

## Impact

Algorithm/strength downgrade of otherwise-strong primitives, undermining the guarantees the
`Aes256` / `Rsa4096` markers imply. Reachability depends on tamper access to key blobs, hence
Medium.

## Remediation

Validate structure and enforce the security-relevant invariants on read:

```csharp
// AES
if (serializedAes is null || serializedAes.Length != 1 + 16 + 32 + 1)
    throw new CryptographicException("Invalid AES key blob length.");
if (serializedAes[0] != (byte)KeyType.Aes256)
    throw new CryptographicException("Unexpected key type.");
var mode = (CipherMode)serializedAes[^1];
if (mode != CipherMode.CBC)                          // whitelist; ideally drop the byte entirely
    throw new CryptographicException("Unsupported cipher mode.");
// key length is now fixed at 32 bytes by the length check above
```

```csharp
// RSA
var rsa = RSA.Create(pp);
if (rsa.KeySize != 4096)
    throw new CryptographicException("Deserialized RSA key is not 4096-bit.");
```

Stronger option: drop the mode byte and hard-code the mode per format version; replace the
hand-rolled RSA format with `RSA.ImportSubjectPublicKeyInfo` / `ImportPkcs8PrivateKey`
(standard, validated). Update the test to assert ECB is **rejected** rather than supported.

## Verification / tests to add

- A blob with mode byte `= 2` (ECB) must throw on deserialize.
- A blob with a 16-byte key segment must throw (not silently yield a 128-bit key).
- An RSA blob encoding a <4096-bit modulus must throw.

## References

- CWE-20, CWE-757, CWE-327 (linked above).
- NIST SP 800-38A (why ECB is inappropriate for general data).
- .NET API: `RSA.ImportSubjectPublicKeyInfo`, `RSA.ImportPkcs8PrivateKey`.
