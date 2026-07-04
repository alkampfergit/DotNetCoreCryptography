---
name: wiki-maintainer
description: Keep the DotNetCoreCryptography README and wiki documentation synchronized with code changes. Use when changing public APIs, encryption formats, key wrapping behavior, security guidance, build/test setup, or examples.
---

# Wiki maintainer

Use this skill whenever a change affects how users should understand or operate
DotNetCoreCryptography.

## Documentation Map

- `README.md`: short project entry point, quick examples, and links to wiki
  pages.
- `wiki/README.md`: wiki index and source map.
- `wiki/quick-start.md`: first-use examples.
- `wiki/envelope-encryption.md`: `SecureEncryptor` behavior and envelope flow.
- `wiki/key-encryptors.md`: `IKeyEncryptor`, KEKs, local/folder/Azure wrapping.
- `wiki/direct-encryption.md`: `StaticEncryptor`, direct symmetric keys, and
  password helpers.
- `wiki/asymmetric-encryption.md`: `AsymmetricSecureEncryptor` and RSA usage.
- `wiki/formats-and-security.md`: wire formats, defaults, compatibility, and
  security guidance.
- `wiki/testing.md`: build, tests, Azure credential requirements, and fixtures.
- `docs/security/`: detailed security-review material; update only when a
  change affects those findings or their status.

## When To Update

Update docs when any of these change:

- Public method signatures, constructors, namespaces, or package layout.
- Default key type, cipher mode, KDF, iteration count, nonce/tag/chunk behavior,
  or envelope format.
- `IKeyEncryptor` behavior or any concrete KEK implementation.
- Azure Key Vault configuration, credential behavior, or algorithm choice.
- Legacy compatibility behavior.
- Test commands, required environment variables, target framework, or build
  scripts.
- Recommended production guidance.

## Process

1. Inspect the code before editing docs. Prefer source files and tests over
   assumptions.
2. Update `README.md` only with concise onboarding material and links.
3. Put detailed explanations in the relevant `wiki/` page.
4. Keep code examples compiling against current APIs.
5. Keep security language explicit: distinguish development-only helpers from
   production recommendations.
6. If a format changes, update both the format page and tamper/compatibility
   testing notes.
7. Run a quick documentation consistency check:

```shell
rg -n "Aes256|AesGcm|AES-GCM|AES-CBC|RsaOaep|RsaOaep256|PBKDF2|600,000|net[0-9]" README.md wiki .claude/skills/wiki-maintainer
rg -n "SecureEncryptor|IKeyEncryptor|DeveloperKeyEncryptor|FolderBasedKeyEncryptor|AzureKeyVaultStoreKeyEncryptor|StaticEncryptor|AsymmetricSecureEncryptor" README.md wiki
```

8. Report which docs were changed and call out any code/doc mismatch found.

## Style

- Keep README brief and navigational.
- Use concrete, runnable C# examples.
- Prefer exact class and method names.
- Avoid promising security properties that are not visible in code or tests.
- Mark legacy APIs as compatibility-only when they are obsolete in source.
