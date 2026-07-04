# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Security

- **SEC-3: key storage at rest hardened.** Key-encryption keys are no longer left
  cleartext with world-readable permissions.
  - Key files are now created with owner-only permissions (`0600`) and their directory
    with `0700` on Unix; on read, a looser-permissioned key file is warned about and
    tightened back to `0600`.
  - Key creation is atomic (`FileMode.CreateNew`), closing the time-of-check/time-of-use
    creation race — a concurrent loser re-reads the existing key instead of overwriting it.
  - `DeveloperKeyEncryptor` encrypts its master key with **DPAPI** (current-user scope)
    on Windows. On non-Windows platforms the key remains cleartext and now requires the
    explicit `allowUnencryptedKeyStore: true` opt-in.
  - `FolderBasedKeyEncryptor` requires a password or the explicit `allowUnencryptedKeys: true`
    opt-in; passwordless (cleartext) storage otherwise throws.

### Changed

- CI (`build-and-publish.yml`) now builds and tests on **both `ubuntu-latest` and
  `windows-latest`** in parallel; NuGet packaging/publishing runs once, only after both
  test legs succeed. `build.ps1` gained `-runTests` / `-runPack` stage switches.

### Fixed

- `build.ps1` NuGet `pack` stamped an empty `FileVersion` due to a typo
  (`$assemblyFileVer` → `$assemblyFileVersion`).

### Breaking changes

- `FolderBasedKeyEncryptor(folder, "")` (empty/`null` password) now throws unless
  `allowUnencryptedKeys: true` is passed.
- `DeveloperKeyEncryptor(folder)` now throws on non-Windows platforms unless
  `allowUnencryptedKeyStore: true` is passed.
- On Windows the developer key file format changed to DPAPI-protected. Pre-existing
  cleartext developer key files remain readable; newly created ones are DPAPI-protected.
