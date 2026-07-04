# Formats and Security Notes

## Current Defaults

- `EncryptionKey.CreateDefault()` creates an AES-256-GCM key.
- Stream encryption is chunked and authenticated.
- Envelope headers are authenticated as associated data.
- Wrapped local data keys use AES-KWP with padding, RFC 5649.
- Azure Key Vault wrapping uses RSA-OAEP-256.
- Built-in `RsaEncryptionKey` wrapping uses RSA OAEP-SHA512.

## Envelope Format

```text
[magic][int32 wrapped-key length][wrapped key][AES-GCM payload]
```

`magic` is the v2 marker `DNC` followed by version byte `0x02`.

The wrapped-key length is bounded before allocation. The wrapped-key header is
then passed as AES-GCM associated data during payload encryption and decryption.

## AES-GCM Payload Format

AES-GCM payloads are chunked:

```text
[7-byte random nonce prefix]
[chunk 0][chunk 1]...[final chunk]
```

Each chunk contains:

```text
[4-byte big-endian header][ciphertext][16-byte tag]
```

The chunk counter and final flag are included in nonce construction. This helps
detect tampering, reordering, and truncation.

## Password Format

```text
[magic][16-byte salt][AES-GCM payload]
```

The salt is random per encryption. PBKDF2 parameters are implied by the v2
format and cannot be changed by editing the payload header.

## Legacy v1 Compatibility

The code still reads legacy v1 formats for backward compatibility. Legacy v1
used AES-CBC and did not provide the same authentication properties as the
current v2 formats.

Do not write new data with obsolete transform-based AES-CBC APIs. They are kept
only so existing data can be decrypted and migrated.

## Operational Notes

- Protect KEKs more strongly than encrypted payloads. Compromising a KEK can
  expose all data keys wrapped by it.
- Do not use `DeveloperKeyEncryptor` in production. Its key is DPAPI-protected on
  Windows but cleartext on other platforms (opt-in via `allowUnencryptedKeyStore`).
- Avoid passwordless `FolderBasedKeyEncryptor` in production; it stores keys in
  cleartext and requires the explicit `allowUnencryptedKeys` opt-in.
- Key files and their directory are created owner-only (`0600` / `0700`) on Unix.
- Prefer Azure Key Vault, HSM-backed storage, or another external KEK provider
  for production service deployments.
- Treat serialized private asymmetric keys and serialized symmetric keys as
  secret material.
