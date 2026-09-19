# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow semantic versioning once formal releases begin.

## [Unreleased]

### Added

- Versioned vault export format based on TAR archives.
- Public `export.json` metadata containing export format version, vault format version, random `vault_id`, and export timestamp.
- SHA-256 sidecar files for export transfer/corruption checks.
- Safe vault import with checksum validation, format-version validation, staged extraction, full cryptographic verification, and atomic publication.
- CLI `export` and `import` commands.
- Isolated regression test suite in `test.py` instead of embedding tests in production vault code.
- A 25-test isolated regression suite covering core operations, CLI transfer flow, successful import/export round trips, and hostile archive/security failure cases.

### Changed

- Shared full-vault verification logic is reused by normal verification and imported-vault verification.
- CLI export options now expose `--destination` with `--dest` as an alias.
- Project documentation now describes the current `0.0.2-alpha` import/export workflow and safety model.
- Production modules now include clearer module-level documentation and export metadata comments.

### Security

- Import rejects missing or invalid checksum sidecars.
- Import rejects missing, malformed, or unsupported export metadata.
- Import rejects unsupported vault format versions.
- Import rejects duplicate TAR entries, absolute paths, parent traversal, symbolic links, hard links, device entries, FIFOs, and unexpected archive members.
- Imported vaults are extracted only into temporary staging directories and are published only after complete encrypted-file verification.
- Import detects tampered encrypted blobs even if the outer TAR checksum is recomputed.
- Existing vault directories are never silently overwritten during import.

## [0.0.1-alpha] - 2026-09-19

### Added

- Encrypted vault creation from a source directory.
- AES-256-GCM authenticated encryption.
- Scrypt-based password key derivation.
- Random 256-bit vault master key.
- HKDF-SHA256 for derived encryption keys.
- Separate encrypted storage for individual files.
- Chunked file encryption to avoid loading entire files into memory.
- Encrypted `manifest.enc` containing vault and file metadata.
- Encrypted `key.enc` containing the protected master key.
- Random `vault_id` values instead of predictable vault directory names.
- Random `file_id` values for stored files.
- Random encrypted storage names for files.
- SHA-256 verification of decrypted file contents.
- AAD binding for vault, file, and chunk integrity.
- Versioned encrypted file formats.
- Validation of chunk order, size, identifiers, and integrity.
- Vault listing.
- Vault opening without decrypting every stored file.
- Single-file extraction.
- Adding a single file without rebuilding the entire vault.
- Removing a single file.
- Renaming a file by updating encrypted metadata only.
- Password changes without re-encrypting all stored file data.
- Full-vault verification.
- Detection of missing, unexpected, corrupted, or modified encrypted blobs.
- Atomic manifest updates.
- Cleanup of incomplete vault creation attempts.
- CLI based on `click`.
- Project tests for core vault operations and selected corruption scenarios.

### Security

- Vault names are no longer exposed through deterministic directory names.
- Original file names and paths are stored only inside encrypted metadata.
- Password changes only re-wrap the master key.
- File integrity is checked using both AES-GCM authentication and SHA-256.
- Full verification can be performed without permanently writing decrypted files to disk.

### Notes

- This is the first public alpha version of the project.
- The project is still under active development.
- The current vault format should be considered experimental until it receives broader testing and external security review.
- The project is partially developed with AI assistance.
- AI-assisted changes are reviewed and verified after implementation using syntax checks, functional tests, integrity tests, and targeted corruption tests where applicable.
