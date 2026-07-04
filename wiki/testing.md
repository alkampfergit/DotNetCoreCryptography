# Testing and Build Notes

## Run Tests

```shell
dotnet test src/DotNetCoreCryptography.sln
```

## Azure Key Vault Tests

Some tests instantiate `AzureKeyVaultStoreKeyEncryptor` and require Azure
credentials. Set these environment variables before running those tests:

```shell
AZURE_TENANT_ID=# Tenant where the application is installed
AZURE_CLIENT_SECRET=# Client secret for the Azure application
AZURE_CLIENT_ID=# Client id for the Azure application
```

The Azure implementation uses `DefaultAzureCredential`, so local developer
identity, managed identity, and service-principal flows may also apply depending
on the environment.

## Compatibility Fixtures

The test project contains v1 fixtures under:

```text
src/DotNetCoreCryptography.Tests/Core/Fixtures/v1/
```

Those fixtures verify that legacy data can still be decrypted while new writes
use v2 authenticated formats.

## Security Regression Tests

`EnvelopeTamperTests` verifies that changing encrypted envelopes fails
decryption. Keep those tests in sync with any format changes.

When changing encryption formats, add tests for:

- Successful round trip.
- Tampered header.
- Tampered wrapped key.
- Tampered nonce/ciphertext/tag.
- Truncated input.
- Legacy v1 compatibility, when the old format should remain readable.
