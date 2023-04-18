# DotNetCoreCryptography

Simple repo to play with Cryptography in .NET core

## Running tests

Some unit tests runs against an Azure KeyVault instance, if you want those tests to succeeds, you need to **set following environment variables**

```shell
AZURE_TENANT_ID=#Tenant where the application is installed
AZURE_CLIENT_SECRET=#Client secret for oauth enterprise azure app
AZURE_CLIENT_ID=#Client id for oauth enterprise azure app
```
