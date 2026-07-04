# Security Findings — Detailed Write-ups

Per-finding deep dives for the security review dated **2026-07-03**
(commit `9b0f088`, branch `feature/modernization`).

Summary report: [`../2026-07-03-security-review.md`](../2026-07-03-security-review.md).

Each document contains the affected code with `file:line` references, root-cause analysis, a
step-by-step exploitation scenario, impact, concrete remediation code, suggested tests, and
references (CWE, NIST/OWASP, .NET APIs).

| ID | Severity | CWE(s) | Title | Status |
|----|----------|--------|-------|--------|
| [SEC-1](SEC-1-unauthenticated-encryption.md) | Critical | 353, 649 | Unauthenticated encryption (missing integrity) | ✅ Fixed (v2 format, 2026-07-03) |
| [SEC-2](SEC-2-weak-kdf.md) | High | 916, 326 | Weak password-based key derivation (PBKDF2-SHA1/1000) | ✅ Fixed for new (v2) data; legacy files weak until re-encrypted |
| [SEC-3](SEC-3-insecure-key-storage.md) | High | 312, 276, 311, 367 | Insecure key storage at rest | ✅ Remediated (0600/0700, atomic create, DPAPI, opt-in) |
| [SEC-4](SEC-4-unbounded-allocation.md) | Medium | 789, 400 | Unbounded allocation from untrusted length | ✅ Fixed |
| [SEC-5](SEC-5-key-deserialization-validation.md) | Medium | 20, 757, 327 | Missing validation on key deserialization (downgrade) | ✅ Fixed |
| [SEC-6](SEC-6-partial-read-iv-salt.md) | Medium | 241, 252 | Partial read of IV / salt | ✅ Fixed |
| [SEC-7](SEC-7-non-constant-time-comparison.md) | Low | 208 | Non-constant-time comparison of secrets | ✅ Fixed |
| [SEC-8](SEC-8-key-material-not-zeroized.md) | Low | 316, 226 | Key material not zeroized | ✅ Fixed (best-effort) |
| [SEC-9](SEC-9-error-information-disclosure.md) | Low | 209, 20 | Information disclosure via errors | ✅ Fixed |

## Suggested remediation order

1. ~~**v2 authenticated, versioned envelope**~~ → ✅ done 2026-07-03 (SEC-1 fixed, SEC-2
   fixed for new data); SEC-3 file-permission hardening also done.
2. ~~**Input-validation hardening**~~ → ✅ done (SEC-4 and SEC-5, incl. RSA key-size validation).
3. ~~**Defense-in-depth**~~ → ✅ done (SEC-7, SEC-8 best-effort, SEC-9).

SEC-6 is already fixed (commit `d57a745`).
