# Security Review — DotNetCoreCryptography

| | |
|---|---|
| **Date of analysis** | 2026-07-03 |
| **Repository** | `alkampfergit/DotNetCoreCryptography` |
| **Branch** | `feature/modernization` |
| **Commit reviewed** | `9b0f088` (code as of the analysis) |
| **Target framework** | `net10.0` |
| **Reviewer** | Claude Opus 4.8 (via Claude Code) |
| **Scope** | Full codebase: `DotNetCoreCryptographyCore`, `DotNetCoreCryptography.Azure`, test project, and CI workflows |

## Methodology

Every source file was read directly. Candidate findings were produced by area-focused
reviewers (symmetric, asymmetric, key management, Azure, utilities, infrastructure) and
then **adversarially verified** — each finding was challenged by an independent pass whose
job was to refute it, and only findings that survived are reported here. Five candidate
issues were refuted during verification and are recorded in
[Investigated and dismissed](#investigated-and-dismissed) so they are not re-raised.

Severity uses an informal Critical/High/Medium/Low scale reflecting exploitability and
impact for a general-purpose encryption library that may process attacker-influenced data
and be deployed on multi-tenant hosts. CWE identifiers are given for cross-referencing.

## Verdict

The RSA/asymmetric layer is soundly constructed (RSA-4096, OAEP-SHA512, no PKCS#1 v1.5).
However, **the symmetric and envelope core is cryptographically broken against an active
attacker**: it provides confidentiality without integrity, and protects keys at rest with a
2010-era password KDF. For a library whose primary public type is named `SecureEncryptor`,
the gap between the implied guarantee and the actual one is the dominant risk. The most
important issues — SEC-1, SEC-2, SEC-3 — are best resolved together as a versioned,
authenticated v2 format.

The CI/CD and supply-chain issues identified during the review have already been remediated
and verified (see [Remediated during this engagement](#remediated-during-this-engagement)).

> **Update (2026-07-03, later the same day):** SEC-1 has been **fixed** on
> `feature/modernization` with the versioned, authenticated v2 format (AES-256-GCM chunked
> payloads with the envelope header as associated data, RFC 5649 AES-KWP key wrapping,
> PBKDF2-SHA256 · 600k for the password format). The symmetric core is no longer
> malleable: every bit-flip, truncation or reordering of v2 ciphertext fails closed, and
> an exhaustive tamper-test suite enforces this. v1 data remains readable for migration
> (and remains unauthenticated by nature). SEC-2 is thereby fixed for newly written data,
> and parts of SEC-4/SEC-5 were hardened in the same change; SEC-3 is untouched. See
> [`details/SEC-1-…#resolution`](details/SEC-1-unauthenticated-encryption.md#resolution).
>
> **Update (SEC-3 remediated):** key storage at rest is now hardened on the same branch —
> `0600` key files / `0700` directories on Unix, atomic race-free key creation, DPAPI
> protection of the developer key on Windows, and a required opt-in for any cleartext
> storage. The test suite runs on Linux and Windows in CI to cover the split. See
> [`details/SEC-3-…#resolution`](details/SEC-3-insecure-key-storage.md#resolution).
>
> **Update (2026-07-04):** SEC-4 is fixed. Envelope wrapped-key lengths are bounded before
> allocation, and RSA key deserialization now rejects negative, zero, oversized, and truncated
> component lengths with `CryptographicException`. See
> [`details/SEC-4-…#resolution`](details/SEC-4-unbounded-allocation.md#resolution).

## Findings summary

The ID column links to the in-report analysis. Each finding also has a **dedicated deep-dive**
(affected code with `file:line`, step-by-step exploitation, remediation code, and suggested
tests) under [`details/`](details/README.md): SEC-1..SEC-9 →
[`details/SEC-1-…`](details/SEC-1-unauthenticated-encryption.md) …
[`details/SEC-9-…`](details/SEC-9-error-information-disclosure.md).

|   ID   | Severity | CWE | Vulnerability | Status |
|--------|----------|-----|---------------|--------|
| [SEC-1](#sec-1--unauthenticated-encryption-critical) | Critical | CWE-353, CWE-649 | Unauthenticated encryption (AES-CBC, cleartext IV, no MAC/AEAD) across every symmetric, hybrid and key-wrapping path | ✅ Fixed (v2 format) |
| [SEC-2](#sec-2--weak-password-based-key-derivation-high) | High | CWE-916, CWE-326 | Weak KDF: PBKDF2-HMAC-SHA1 at 1000 iterations protecting keys at rest | ✅ Fixed for new (v2) data — PBKDF2-SHA256 · 600k; pre-existing files stay weak until re-encrypted |
| [SEC-3](#sec-3--insecure-key-storage-at-rest-high) | High | CWE-312, CWE-276 | Keys stored in cleartext with default/world-readable permissions; TOCTOU creation race | ✅ Remediated — 0600/0700 perms, atomic CreateNew, DPAPI on Windows, opt-in for cleartext |
| [SEC-4](#sec-4--unbounded-allocation-from-untrusted-length-medium) | Medium | CWE-789, CWE-400 | Attacker-controlled 32-bit length drives multi-GB pre-allocation (DoS) | ✅ Fixed |
| [SEC-5](#sec-5--missing-validation-on-key-deserialization-medium) | Medium | CWE-20, CWE-757, CWE-327 | Key deserialization accepts arbitrary cipher mode (incl. ECB), does not enforce key sizes → algorithm/size downgrade | Partially fixed (AES: CBC-only whitelist + exact length; RSA validation still open) |
| [SEC-6](#sec-6--partial-read-of-iv--salt-medium) | Medium | CWE-241 | Partial `Stream.Read` of IV/salt yields zero-filled key material / silent corruption | ✅ Fixed |
| [SEC-7](#sec-7--non-constant-time-comparison-of-secrets-low) | Low | CWE-208 | Non-constant-time comparison of secret key material | Open (defense-in-depth) |
| [SEC-8](#sec-8--key-material-not-zeroized-low) | Low | CWE-316 | Key material not zeroized; lingers on the managed heap | Open (defense-in-depth) |
| [SEC-9](#sec-9--information-disclosure-via-errors-low) | Low | CWE-209 | Storage path leaked via exceptions; malformed input throws wrong exception type | Open |

---

## Detailed findings

### SEC-1 — Unauthenticated encryption (Critical)

**CWE-353** (Missing Support for Integrity Check), **CWE-649** (Reliance on Obfuscation/
Encryption Without Integrity).

**Locations**
- `src/DotNetCoreCryptographyCore/AesEncryptionKey.cs` — `CreateEncryptor`/`CreateDecryptor` use `Aes.Create()` defaults (CBC + PKCS7); the IV is written to the stream in cleartext.
- `src/DotNetCoreCryptographyCore/StaticEncryptor.cs` — all stream and password paths.
- `src/DotNetCoreCryptographyCore/SecureEncryptor.cs` — envelope format `[int32 len][wrapped key][IV][CBC ciphertext]`.
- `src/DotNetCoreCryptographyCore/AsymmetricSecureEncryptor.cs` — hybrid format, same shape.
- `src/DotNetCoreCryptographyCore/Concrete/FolderBasedKeyEncryptor.cs` and `DeveloperKeyEncryptor.cs` — wrap data-encryption keys through the same CBC path, so **wrapped keys are themselves malleable**.

**Description**
There is no MAC and no AEAD anywhere in the library (a repository-wide search for HMAC/GCM
in `src/` returns nothing). All symmetric encryption is AES-CBC with the IV stored in the
clear ahead of the ciphertext.

**Exploitation**
An attacker who can modify ciphertext at rest or in transit can:
1. **Bit-flip the first plaintext block** deterministically by XORing the cleartext IV (classic CBC malleability).
2. **Truncate** at block boundaries with no detection.
3. Mount a **padding-oracle attack** (CWE-649) for full plaintext recovery if the consuming application distinguishes PKCS7 padding failures (`CryptographicException`) from other errors.
4. Tamper with **wrapped key blobs**, since they use the same unauthenticated path.

No test exercises tampered or truncated ciphertext, confirming integrity was never a design
goal — yet the public type is named `SecureEncryptor` and is published to NuGet.

**Remediation**
Adopt authenticated encryption:
- Encrypt payloads with **`AesGcm`** (12-byte random nonce where the IV is today, 16-byte tag), binding the envelope header (version, wrapped-key length, key id) as associated data.
- Wrap data keys with an integrity-checked mechanism — **.NET 10 `Aes.EncryptKeyWrapPadded`/`DecryptKeyWrapPadded`** (RFC 5649), which fails closed on tampering.
- Introduce a format-version byte so existing v1 data can still be read while new data is authenticated.
- Add tests asserting that any bit-flip in header, wrapped key, IV, or ciphertext causes decryption to fail.

**Resolution — ✅ Fixed (2026-07-03, `feature/modernization`)**
Implemented exactly along these lines as the **v2 format**: default key switched to
`AesGcmEncryptionKey` (AES-256-GCM, chunked STREAM construction with per-chunk counter and
final-chunk flag, so bit-flips, truncation, reordering and trailing data all fail closed);
envelope `[magic][len][wrapped key][GCM payload]` with the whole header authenticated as
associated data; data keys wrapped with RFC 5649 AES-KWP; uniform
`CryptographicException("Decryption failed.")` on every failure; v1 data auto-detected and
still readable. Verified by an exhaustive tamper suite (`AesGcmEncryptionKeyTests`,
`EnvelopeTamperTests`, flipping every bit / truncating at every length) and by
`V1CompatibilityTests` decrypting fixtures generated with the pre-fix library. Full details:
[`details/SEC-1-…#resolution`](details/SEC-1-unauthenticated-encryption.md#resolution).

---

### SEC-2 — Weak password-based key derivation (High)

**CWE-916** (Use of Password Hash With Insufficient Computational Effort), **CWE-326**
(Inadequate Encryption Strength).

**Location** — `src/DotNetCoreCryptographyCore/EncryptionUtils.cs`, `DeriveKeyAndIv`
(lines ~38–49), reachable via `GetEncryptorFromPassword`/`GetDecryptorFromPassword` →
`StaticEncryptor.AesEncryptWithPassword`/`AesDecryptWithPassword` →
`FolderBasedKeyEncryptor.Encrypt`/`Decrypt`.

**Description**
Password-based protection uses PBKDF2-HMAC-**SHA1** at **1000 iterations**, deriving both the
32-byte key and 16-byte IV from a single PBKDF2 stream. Current OWASP guidance is ≥600,000
iterations for SHA-256 (≥1,300,000 for SHA-1). The per-file salt is stored in cleartext as
the first 16 bytes of each encrypted key file.

**Exploitation**
This is the entire at-rest protection of `FolderBasedKeyEncryptor`. An attacker who copies
the key folder can brute-force typical passwords offline at GPU speed — roughly three orders
of magnitude cheaper than modern parameters would allow — recovering every master key and,
through them, every wrapped data key.

**Status note**
When the obsolete `Rfc2898DeriveBytes` constructor was replaced with the static `Pbkdf2`
one-shot (a build-warning fix, SYSLIB0060), the algorithm and parameters (SHA1/1000) were
**deliberately preserved for backward compatibility** and annotated with a `WARNING` comment
in the source. Strengthening them is a breaking change to the on-disk format and should ride
with the SEC-1 format-version bump.

**Remediation**
`Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32)` with
≥600,000 iterations; derive only the key from the KDF and use a random per-encryption IV;
store the iteration count and hash id in the file header so parameters can be raised later
without breaking existing data. Consider Argon2id via a vetted library for new formats.

---

### SEC-3 — Insecure key storage at rest (High)

**CWE-312** (Cleartext Storage of Sensitive Information), **CWE-276** (Incorrect Default
Permissions), **CWE-311** (Missing Encryption of Sensitive Data), **CWE-367** (TOCTOU).

**Locations**
- `src/DotNetCoreCryptographyCore/Concrete/DeveloperKeyEncryptor.cs:26,29` — master AES key written in cleartext via `File.WriteAllBytes`; `File.Exists → WriteAllBytes` creation race.
- `src/DotNetCoreCryptographyCore/Concrete/FolderBasedKeyEncryptor.cs:131` — key files written in cleartext whenever the password is empty (an explicitly supported and tested mode).
- `src/DotNetCoreCryptographyCore/Utils/InternalUtils.cs:11` — directories created with default permissions.

**Description**
Key files and their containing directories are created with default permissions. On Linux/
macOS a typical umask yields `0755` directories and `0644` files (world-readable). The
developer store always keeps its master key in cleartext; the folder store does so whenever
no password is configured.

**Exploitation**
On a multi-user host or shared-volume container, any co-resident local user can read the
key-encryption key directly (`{folder}/developerKeyValueStore.key`, `{folder}/1.key`) and
decrypt all protected data. The `File.Exists`/`File.WriteAllBytes` sequence additionally
lets two concurrently constructed instances overwrite or read a partially written key.

**Remediation**
Create key files through `new FileStream(path, new FileStreamOptions { Mode =
FileMode.CreateNew, Access = FileAccess.Write, UnixFileMode = UnixFileMode.UserRead |
UnixFileMode.UserWrite })` (owner-only `0600`, no chmod TOCTOU window; `CreateNew` also
resolves the overwrite race). Create the directory with the `UnixFileMode` overload of
`Directory.CreateDirectory`, guarded by `OperatingSystem.IsWindows()`. On Windows, consider
DPAPI (`ProtectedData`) for the developer key. Emit a loud warning (or require an explicit
opt-in) when cleartext storage is selected.

---

### SEC-4 — Unbounded allocation from untrusted length (Medium)

**CWE-789** (Memory Allocation with Excessive Size Value), **CWE-400** (Uncontrolled
Resource Consumption).

**Locations**
- `src/DotNetCoreCryptographyCore/SecureEncryptor.cs:72-73`
- `src/DotNetCoreCryptographyCore/AsymmetricSecureEncryptor.cs:64-65`
- `src/DotNetCoreCryptographyCore/AsymmetricEncryptionUtils.cs:83-102` (`DeserializeToRsa`, every component length)

**Description**
A 32-bit length prefix is read from the untrusted input and passed straight to
`BinaryReader.ReadBytes(length)`, which allocates `new byte[length]` up front before reading.

**Exploitation**
A 4-byte malicious prefix of `0x7FFFFFFF` forces an attempted ~2 GB allocation
(`OutOfMemoryException` / LOH pressure) from a tiny input; a negative value throws
`ArgumentOutOfRangeException` rather than a meaningful `CryptographicException`. For the only
supported key types the wrapped key is a known small size, so no legitimate large value
exists.

**Remediation**
Validate each length against a tight upper bound (e.g. the RSA modulus size for the key in
use, or ≤ a few KB) and throw `CryptographicException` before allocating; verify `ReadBytes`
returned exactly the requested count.

**Resolution**
Fixed on 2026-07-04. Envelope wrapped-key lengths are checked through
`CryptoFormat.ValidateWrappedKeyLength`, and `DeserializeToRsa` uses bounded component reads
before allocation. Regression tests cover oversized, negative, and truncated length prefixes
for the RSA and envelope paths.

---

### SEC-5 — Missing validation on key deserialization (Medium)

**CWE-20** (Improper Input Validation), **CWE-757** (Selection of Less-Secure Algorithm
During Negotiation), **CWE-327** (Use of a Broken or Risky Cryptographic Algorithm).

**Locations**
- `src/DotNetCoreCryptographyCore/EncryptionUtils.cs` — `Serialize`/`DeserializeToAes`.
- `src/DotNetCoreCryptographyCore/AsymmetricEncryptionUtils.cs` — `DeserializeToRsa`.

**Description**
`DeserializeToAes` derives the key length from the blob length (a 34-byte blob silently
yields a 128-bit key still marked `Aes256`), and honors the trailing cipher-mode byte
verbatim — so a blob with `Mode = ECB` round-trips and produces **ECB encryption of user
data** (deterministic, reveals plaintext block patterns). `Serialize` stamps `Aes256`
without checking `KeySize == 256`. `DeserializeToRsa` validates only the type byte, never
that the modulus is actually 4096-bit. The repo's own test suite asserts ECB round-trip
support (`EncryptionUtilsTests.SerializationMaintainModeOfOperation`), entrenching the
behavior.

**Exploitation**
Because key blobs are wrapped with the unauthenticated path (SEC-1), an attacker able to
tamper with stored key material can downgrade the algorithm (to ECB) or key size without
detection.

**Remediation**
Validate the exact expected length (50 bytes for Aes256), require a 32-byte key for the
`Aes256` marker, restrict the mode to CBC/GCM (or drop the mode byte and fix it per format
version), and verify `Modulus.Length == 512` before `RSA.Create(pp)`. Remove the ECB test
assertion (or invert it to assert ECB is rejected).

---

### SEC-6 — Partial read of IV / salt (Medium) — ✅ Fixed

**CWE-241** (Improper Handling of Unexpected Data Type / incomplete read).

**Locations** — `src/DotNetCoreCryptographyCore/AesEncryptionKey.cs` (IV),
`src/DotNetCoreCryptographyCore/StaticEncryptor.cs` (salt, sync + async).

**Description**
The IV and salt were read with `Stream.Read(...)` while ignoring the return value.
`Stream.Read` may return fewer bytes than requested (real for `NetworkStream`,
`DeflateStream`, `CryptoStream`, pipes), leaving the tail of the IV/salt zero-filled and the
stream misaligned — producing silent corruption or a confusing downstream padding exception.

**Resolution**
Replaced with `ReadExactly` / `ReadExactlyAsync`, which throw `EndOfStreamException` on
truncated input instead of proceeding with a partially filled buffer. This also cleared the
`CA2022` analyzer warnings introduced by the net10 retarget. Fixed in commit `d57a745`.

---

### SEC-7 — Non-constant-time comparison of secrets (Low)

**CWE-208** (Observable Timing Discrepancy).

**Locations** — `src/DotNetCoreCryptographyCore/AesEncryptionKey.cs` (`Equals`, LINQ
`SequenceEqual` on `_key.Key`/`IV`), `src/DotNetCoreCryptographyCore/AsymmetricEncryptionUtils.cs`
(`KeyEqual`).

**Description**
Secret key material is compared with early-exit `SequenceEqual`, which is not
constant-time. Currently these comparisons are only reached from tests and do not gate a
security decision, so exploitability is speculative — reported as defense-in-depth for a
published cryptographic library.

**Remediation**
Use `CryptographicOperations.FixedTimeEquals(ReadOnlySpan<byte>, ReadOnlySpan<byte>)`.

---

### SEC-8 — Key material not zeroized (Low)

**CWE-316** (Cleartext Storage of Sensitive Information in Memory).

**Locations** — `AsymmetricSecureEncryptor` (`serializedKey`, `key.Serialize()`),
`AsymmetricEncryptionUtils.Serialize`/`DeserializeToRsa` (RSA private params),
`EncryptionUtils` (PBKDF2-derived key/IV), `AzureKeyVaultStoreKeyEncryptor` (`result.Plaintext`).

**Description**
Transient key buffers are abandoned to the garbage collector without being wiped, so
data-encryption keys and RSA private parameters can persist on the managed heap and appear
in crash dumps or the page file. Requires an independent memory-disclosure primitive to
exploit, hence Low — but relevant hygiene for a library whose sole purpose is key handling.

**Remediation**
Wrap temporary key buffers in `try/finally` with
`CryptographicOperations.ZeroMemory(Span<byte>)` after use.

---

### SEC-9 — Information disclosure via errors (Low)

**CWE-209** (Generation of Error Message Containing Sensitive Information).

**Locations** — `src/DotNetCoreCryptographyCore/Concrete/FolderBasedKeyEncryptor.cs`
(`DecryptAsync`/`GetKey`), `src/DotNetCoreCryptographyCore/EncryptionKey.cs:27` and
`src/DotNetCoreCryptographyCore/AsymmetricEncryptionKey.cs:14`.

**Description**
A tampered/unknown key number surfaces as a `FileNotFoundException`/`DirectoryNotFoundException`
whose message leaks the key-folder path. The public deserialization factories index
`serializedKey[0]` with no guard, so null/empty input throws `NullReferenceException` /
`IndexOutOfRangeException` instead of a deliberate, catchable `CryptographicException`
(reachable from a truncated key file, e.g. after an interrupted `File.WriteAllBytes`).

**Remediation**
Translate missing/unknown key numbers into a `CryptographicException` that does not include
the storage path; add `ArgumentNullException.ThrowIfNull` plus a minimum-length check
throwing `CryptographicException` in the factories.

---

## Remediated during this engagement

The following process / supply-chain security issues were fixed and verified. All three CI
workflows pass on the reviewed commit.

| Area | Issue | CWE | Resolution | Commit |
|------|-------|-----|-----------|--------|
| Release pipeline | Every push to `feature/*` and `hotfix/*` published unreviewed packages to nuget.org | CWE-284 | Publishing gated to `master` / `release/*` only | `df335a1` |
| Release pipeline | `coverallsapp/github-action@master` — mutable third-party ref in a secret-bearing job | CWE-829 | Pinned to `@v2` | `df335a1` |
| Both pipelines | `NUGET_API_KEY` / `SONAR_TOKEN` interpolated onto the command line | CWE-214 | Passed via `env:` | `df335a1` |
| All workflows | No `permissions:` block → default over-privileged `GITHUB_TOKEN` | CWE-250 | Least-privilege `permissions` on every workflow | `df335a1` |
| CodeQL | Retired `github/codeql-action@v2` → SAST silently dead | — | Upgraded to `@v3` + `security-events: write` + net10 SDK | `df335a1` |

Related build hardening (`d57a745`): removed obsolete `RNGCryptoServiceProvider`
(SYSLIB0023) in favor of `RandomNumberGenerator` (still a CSPRNG — no behavior change), and
fixed the partial-read defect (SEC-6).

> Recommended further supply-chain hardening: pin every GitHub Action to a full commit SHA
> (not just a tag), and enable `NuGetAudit`/`NuGetAuditMode=all` with the crypto-misuse
> analyzers (CA5350–CA5404) promoted to build errors.

## Positives (verified, no issue found)

- **RSA padding is correct**: `RSAEncryptionPadding.OaepSHA512` in code, `RsaOaep256` on Azure Key Vault. No PKCS#1 v1.5 encryption padding anywhere. RSA-4096 enforced on serialize.
- **CSPRNG throughout**: IVs and salts come from `RandomNumberGenerator`; no use of `System.Random`.
- **No hardcoded cryptographic keys or secrets** in source (the "developer key" is randomly generated, not embedded).
- **No injection surface**: key file names are built from an `int` key number (no path traversal); `System.Text.Json` deserialization of `info.json` is non-polymorphic and safe by default; no XML/XXE, SQL, or process execution.

## Investigated and dismissed

Refuted during adversarial verification; recorded to prevent re-raising:

1. **Azure argument validation** — `new Uri()` and the Key Vault SDK already fail fast with named exceptions; missing throw-helpers are ergonomics, not a vulnerability.
2. **Hardcoded live Azure Key Vault test** — documented in the README (requires `AZURE_*` env vars) and injected in CI; a test-hygiene / DX concern, not a code defect.
3. **`KeyEqual` timing channel** — not reachable in any security decision, and an RSA private exponent is mathematically determined by `P,Q`, so chosen-prefix enumeration is infeasible.
4. **Comparing two public-only RSA keys throws `NullReferenceException`** — empirically does **not** throw on net10/C# 14: `byte[].SequenceEqual` binds to the span overload and `null → empty span`. (Fragility note: correctness now depends on C# 14 overload resolution; pinning `LangVersion ≤ 13` would reintroduce the crash — a `FixedTimeEquals`/null-guard fix is advisable.)
5. **`Aes.Create()` not disposed in the password methods** — key generation is lazy and these instances are only used via `CreateEncryptor(key, iv)`, so no key material resides in the instance and net10's managed `Aes` holds no native handle; the `ICryptoTransform` is disposed. No security impact.

## Recommended remediation roadmap

1. ~~**v2 authenticated, versioned envelope format**~~ — ✅ **Done (2026-07-03)** for the
   cryptographic part: AES-GCM payloads with the header as associated data, AES-KWP
   (RFC 5649) key wrapping, PBKDF2-SHA256 · 600k (parameters implied by the format-version
   byte), v1 kept read-only for migration. **Still to do from this item:** owner-only file
   permissions (SEC-3).
2. **Input-validation hardening** (SEC-4, SEC-5) — SEC-4 is fixed; SEC-5 is partially done
   (AES cipher mode whitelisted to CBC, exact serialized key lengths enforced). Remaining:
   RSA semantic validation, including modulus-size validation.
3. **Defense-in-depth** (SEC-7, SEC-8, SEC-9) — `FixedTimeEquals`, `ZeroMemory`, and
   `CryptographicException`-typed failures that do not leak storage paths. (The new
   `AesGcmEncryptionKey` already uses `FixedTimeEquals`, zeroizes its key on dispose, and
   the new decrypt paths fail uniformly; the pre-existing locations are unchanged.)
4. **Supply-chain** — SHA-pin all GitHub Actions; enable NuGet auditing and the crypto
   analyzers as build errors.

## Appendix — files reviewed

**`DotNetCoreCryptographyCore`**: `EncryptionKey.cs`, `AesEncryptionKey.cs`,
`EncryptionUtils.cs`, `StaticEncryptor.cs`, `KeyType.cs`, `AsymmetricEncryptionKey.cs`,
`RsaEncryptionKey.cs`, `AsymmetricEncryptionUtils.cs`, `AsymmetricSecureEncryptor.cs`,
`AsymmetricKeyType.cs`, `SecureEncryptor.cs`, `SecureEncryptorExtensionMethods.cs`,
`IKeyEncryptor.cs`, `Concrete/DeveloperKeyEncryptor.cs`, `Concrete/FolderBasedKeyEncryptor.cs`,
`Utils/CertificateStoreHelpers.cs`, `Utils/HexEncoding.cs`, `Utils/InternalUtils.cs`.

**`DotNetCoreCryptography.Azure`**: `AzureKeyVaultStoreKeyEncryptor.cs`.

**Tests**: all files under `DotNetCoreCryptography.Tests/Core`.

**CI**: `.github/workflows/build-and-publish.yml`, `codeql-analysis.yml`, `sonar-cloud.yml`.

---

*This report reflects the state of the code at commit `9b0f088` on 2026-07-03. Findings
marked "Open" had not been remediated as of that commit.*
