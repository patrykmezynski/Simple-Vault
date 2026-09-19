"""High-level vault operations for creating, modifying, exporting and importing encrypted vaults.

This module coordinates encrypted storage, manifest handling, integrity verification
and safe import/export operations. Cryptographic primitives remain implemented in
``src.crypto`` while manifest serialization is handled by ``src.manifest``.
"""

#standard library imports
from pathlib import Path, PurePosixPath
from hashlib import sha256
from datetime import datetime
from dataclasses import asdict

import secrets
import shutil
import tarfile
import io
import json
import tempfile

#local imports
from src import vault_config
from src import crypto
from src import manifest as mf


VAULT_ROOT = Path("vaults")

def _calculate_file_sha256(file_path: Path) -> str:
    """
    Calculate SHA-256 hash of a file without loading
    the entire file into memory.

    Args:
        file_path (Path): Path to the file.

    Returns:
        str: SHA-256 hash as hexadecimal string.
    """

    file_hash = sha256()

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)

            if not chunk:
                break

            file_hash.update(chunk)

    return file_hash.hexdigest()

def _format_timestamp(timestamp: float) -> str:
    """Convert filesystem timestamp to ISO date."""
    return datetime.fromtimestamp(timestamp).isoformat(timespec="seconds")


def _iter_vault_paths() -> list[Path]:
    """
    Return directories that may contain encrypted vaults.

    Vault directory names are random identifiers and do not contain the
    original vault name.

    Returns:
        list[Path]: Vault directories found inside the vault root.
    """

    # No vault directory means there are simply no stored vaults yet.
    if not VAULT_ROOT.exists():
        return []

    return sorted(
        path
        for path in VAULT_ROOT.iterdir()
        if path.is_dir()
    )


def _normalize_vault_file_path(file_path: str) -> str:
    """
    Normalize and validate a logical file path stored inside the vault.

    Paths are always stored in POSIX form so the same manifest works on
    Windows and Linux. Absolute paths and parent traversal are rejected.

    Args:
        file_path (str): Path visible inside the vault.

    Returns:
        str: Valid normalized relative path.

    Raises:
        ValueError: If the path is empty, absolute or unsafe.
    """

    # Convert Windows separators to the portable vault path format.
    normalized = file_path.strip().replace("\\", "/")

    if not normalized:
        raise ValueError("Vault file path cannot be empty.")

    path = PurePosixPath(normalized)

    if path.is_absolute():
        raise ValueError("Vault file path must be relative.")

    if any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("Vault file path contains an unsafe path component.")

    # Reject Windows drive-like prefixes such as C: even on non-Windows hosts.
    if path.parts and ":" in path.parts[0]:
        raise ValueError("Vault file path cannot contain a drive prefix.")

    return path.as_posix()


def _unlock_vault_path(
    vault_path: Path,
    password: str
) -> tuple[bytes, bytes, vault_config.VaultManifest]:
    """
    Unlock one vault directory and load its authenticated manifest.

    Args:
        vault_path (Path): Physical vault directory.
        password (str): Password used to unlock key.enc.

    Returns:
        tuple: Master key, vault_id and decrypted VaultManifest.

    Raises:
        FileNotFoundError: If required vault files do not exist.
        ValueError: If password or authenticated data validation fails.
    """

    # Unlock the random master key using the password.
    master_key, vault_id = crypto.load_master_key(
        vault_path / "key.enc",
        password
    )

    # Load the encrypted manifest using the unlocked master key.
    manifest = mf.load_manifest(
        vault_path,
        master_key,
        vault_id
    )

    return master_key, vault_id, manifest


def _find_vault(
    vault_name: str,
    password: str
) -> tuple[Path, bytes, bytes, vault_config.VaultManifest]:
    """
    Find a vault by decrypting candidate manifests with the provided password.

    Vault names are no longer stored as directory hashes. Because the name is
    available only inside encrypted manifest.enc, the program must try stored
    vaults until it finds an authenticated manifest with the requested name.

    Args:
        vault_name (str): Original encrypted vault name.
        password (str): Password used to unlock candidate vaults.

    Returns:
        tuple: Vault path, master key, vault_id and decrypted manifest.

    Raises:
        FileNotFoundError: If no matching vault can be unlocked.
        ValueError: If more than one matching vault exists.
    """

    matches = []

    for vault_path in _iter_vault_paths():
        try:
            master_key, vault_id, manifest = _unlock_vault_path(
                vault_path,
                password
            )
        except (FileNotFoundError, ValueError):
            # A different password, unsupported folder or corrupted candidate
            # cannot reveal its encrypted vault name.
            continue

        if manifest.vault_name == vault_name:
            matches.append(
                (
                    vault_path,
                    master_key,
                    vault_id,
                    manifest
                )
            )

    if not matches:
        raise FileNotFoundError(
            f"Vault '{vault_name}' was not found or password is invalid."
        )

    if len(matches) > 1:
        raise ValueError(
            f"More than one vault named '{vault_name}' can be unlocked "
            "with this password."
        )

    return matches[0]


def _refresh_directory_metadata(
    manifest: vault_config.VaultManifest
) -> None:
    """
    Update logical directory entries after file add, remove or rename.

    Existing directories are preserved, including empty directories. Missing
    parent directories introduced by add or rename are created automatically.
    Directory sizes are recalculated from current manifest files.

    Args:
        manifest (vault_config.VaultManifest): Manifest being modified.
    """

    current_date = datetime.now().isoformat(timespec="seconds")

    # Preserve metadata for directories that already exist in the manifest.
    directory_map = {
        directory.path: directory
        for directory in manifest.directories
    }

    # Add missing parent directories required by current file paths.
    for file in manifest.files:
        path = PurePosixPath(file.path)

        for parent in path.parents:
            if parent == PurePosixPath("."):
                continue

            parent_path = parent.as_posix()

            if parent_path not in directory_map:
                directory_map[parent_path] = vault_config.DirectoryEntry(
                    path=parent_path,
                    size=0,
                    date_created=current_date,
                    date_modified=current_date
                )

    # Recalculate total recursive size for every logical directory.
    for directory in directory_map.values():
        prefix = f"{directory.path}/"

        directory.size = sum(
            file.size
            for file in manifest.files
            if file.path.startswith(prefix)
        )

    manifest.directories = sorted(
        directory_map.values(),
        key=lambda directory: directory.path
    )


def _verify_vault_path(
    vault_path: Path,
    master_key: bytes,
    vault_id: bytes,
    manifest: vault_config.VaultManifest
) -> vault_config.VaultVerifyResult:
    """
    Verify one unlocked vault directory without extracting plaintext files.

    The caller provides an already authenticated manifest and the matching
    master key and vault identifier. Every encrypted data blob is then
    decrypted chunk by chunk in memory and checked against file metadata.

    Args:
        vault_path (Path): Physical vault directory to verify.
        master_key (bytes): Unlocked vault master key.
        vault_id (bytes): Authenticated random vault identifier.
        manifest (vault_config.VaultManifest): Authenticated vault manifest.

    Returns:
        vault_config.VaultVerifyResult: Summary of successfully verified data.

    Raises:
        FileNotFoundError: If the vault data directory or a blob is missing.
        ValueError: If metadata, file layout or cryptographic verification fails.
    """

    data_path = vault_path / "data"

    if not data_path.exists() or not data_path.is_dir():
        raise FileNotFoundError(
            f"Vault data directory does not exist: '{data_path}'."
        )

    # Validate unique manifest fields before touching encrypted file data.
    file_paths = [file.path for file in manifest.files]
    storage_names = [file.storage_name for file in manifest.files]
    file_ids = [file.file_id for file in manifest.files]
    directory_paths = [directory.path for directory in manifest.directories]

    if len(file_paths) != len(set(file_paths)):
        raise ValueError("Manifest contains duplicate file paths.")

    if len(storage_names) != len(set(storage_names)):
        raise ValueError("Manifest contains duplicate storage names.")

    if len(file_ids) != len(set(file_ids)):
        raise ValueError("Manifest contains duplicate file identifiers.")

    if len(directory_paths) != len(set(directory_paths)):
        raise ValueError("Manifest contains duplicate directory paths.")

    expected_storage_names = set()

    for file in manifest.files:
        # Revalidate logical paths before they are trusted by verification code.
        if _normalize_vault_file_path(file.path) != file.path:
            raise ValueError(
                f"Manifest contains non-normalized file path: '{file.path}'."
            )

        # storage_name must be one plain file name inside data/.
        storage_path = Path(file.storage_name)
        if (
            storage_path.name != file.storage_name
            or "/" in file.storage_name
            or "\\" in file.storage_name
            or not file.storage_name.endswith(".enc")
        ):
            raise ValueError(
                f"Invalid encrypted storage name: '{file.storage_name}'."
            )

        expected_storage_names.add(file.storage_name)

        try:
            file_id = bytes.fromhex(file.file_id)
        except ValueError as e:
            raise ValueError(
                f"Invalid file_id for '{file.path}'."
            ) from e

        encrypted_path = data_path / file.storage_name

        # Verify complete encrypted file without writing plaintext to disk.
        crypto.verify_file(
            encrypted_path,
            master_key,
            vault_id,
            file_id,
            file.size,
            file.sha256
        )

    # Detect orphan or unexpected files that are not referenced by manifest.
    actual_storage_names = {
        path.name
        for path in data_path.iterdir()
        if path.is_file()
    }

    if actual_storage_names != expected_storage_names:
        missing = sorted(
            expected_storage_names - actual_storage_names
        )
        unexpected = sorted(
            actual_storage_names - expected_storage_names
        )

        details = []
        if missing:
            details.append(
                "missing: " + ", ".join(missing)
            )
        if unexpected:
            details.append(
                "unexpected: " + ", ".join(unexpected)
            )

        raise ValueError(
            "Vault data directory does not match manifest ("
            + "; ".join(details)
            + ")"
        )

    # Verify directory sizes against current logical file paths.
    for directory in manifest.directories:
        normalized_directory = _normalize_vault_file_path(
            directory.path
        )

        if normalized_directory != directory.path:
            raise ValueError(
                f"Manifest contains non-normalized directory path: "
                f"'{directory.path}'."
            )

        prefix = f"{directory.path}/"
        calculated_size = sum(
            file.size
            for file in manifest.files
            if file.path.startswith(prefix)
        )

        if directory.size != calculated_size:
            raise ValueError(
                f"Directory size does not match manifest files: "
                f"'{directory.path}'."
            )

    return vault_config.VaultVerifyResult(
        vault_name=manifest.vault_name,
        file_count=manifest.file_count,
        directory_count=manifest.directory_count,
        total_size=manifest.size
    )


def export_vault(
        vault_name: str,
        password: str,
        destination: str = "exports"
) -> Path:
    """
    Export an existing vault to a TAR archive
    in the selected destination directory.

    Args:
        vault_name (str): Name of the vault to export.
        password (str): Password used to unlock the vault.
        destination (str): Directory where the exported vault will be saved.
                           Defaults to "exports".

    Returns:
        Path: Path to the exported TAR archive.

    Raises:
        FileNotFoundError: If the vault does not exist.
        FileExistsError: If the export files already exist.
        ValueError: If the password is invalid or the vault is corrupted.
    """

    # Find and unlock the requested vault.
    vault_path, _, _, manifest = _find_vault(
        vault_name,
        password
    )

    destination_path = Path(destination)

    # Create destination directory if needed.
    destination_path.mkdir(
        parents=True,
        exist_ok=True
    )

    # Use the random vault ID instead of exposing the vault name.
    export_path = (
        destination_path
        / f"{vault_path.name}.tar"
    )

    hash_path = export_path.with_suffix(
        export_path.suffix + ".sha256"
    )

    # Do not overwrite existing export files.
    if export_path.exists():
        raise FileExistsError(
            f"Export path already exists: '{export_path}'"
        )

    if hash_path.exists():
        raise FileExistsError(
            f"Export hash already exists: '{hash_path}'"
        )

    # Create export metadata.
    export_metadata = vault_config.VaultExportMetadata(
        format=vault_config.VAULT_EXPORT_FORMAT,
        version=vault_config.VAULT_EXPORT_VERSION,
        vault_format_version=manifest.format_version,
        vault_id=manifest.vault_id,
        created_at=datetime.now().isoformat(timespec="seconds")
    )

    json_data = json.dumps(
        asdict(export_metadata),
        indent=4
    ).encode("utf-8")

    try:
        # Create TAR archive containing the complete encrypted vault.
        with tarfile.open(export_path, "w") as tar:

            tar.add(
                vault_path,
                arcname=vault_path.name
            )

            # Create export metadata file inside TAR archive.
            export_info = tarfile.TarInfo(
                name="export.json"
            )

            export_info.size = len(json_data)

            tar.addfile(
                export_info,
                io.BytesIO(json_data)
            )

        # Calculate SHA-256 of the complete export archive.
        archive_hash = _calculate_file_sha256(
            export_path
        )

        # Save archive hash next to the exported vault.
        hash_path.write_text(
            archive_hash,
            encoding="utf-8"
        )

    except Exception:
        # Remove incomplete export files if something failed.
        if export_path.exists():
            export_path.unlink()

        if hash_path.exists():
            hash_path.unlink()

        raise

    return export_path

def import_vault(
        archive: str,
        password: str,
) -> Path:
    """
    Import and verify an exported vault archive.

    The archive checksum and export metadata are validated before extraction.
    TAR members are checked for unsafe paths and unsupported entry types.
    The vault is extracted into a temporary directory, cryptographically
    verified and moved into the vault directory only after all checks pass.

    Args:
        archive (str): Path to the exported TAR archive.
        password (str): Password used to unlock and verify the imported vault.

    Returns:
        Path: Path to the imported vault directory.

    Raises:
        FileNotFoundError: If archive or checksum file does not exist.
        FileExistsError: If the vault already exists.
        ValueError: If checksum, metadata, TAR structure or vault verification
                    fails.
    """

    archive_path = Path(archive)

    # Validate export archive path.
    if not archive_path.exists():
        raise FileNotFoundError(
            f"Export archive does not exist: '{archive_path}'"
        )

    if not archive_path.is_file():
        raise ValueError(
            f"Export archive is not a file: '{archive_path}'"
        )

    # Locate checksum stored next to the export archive.
    hash_path = archive_path.with_suffix(
        archive_path.suffix + ".sha256"
    )

    if not hash_path.exists():
        raise FileNotFoundError(
            f"Export checksum does not exist: '{hash_path}'"
        )

    if not hash_path.is_file():
        raise ValueError(
            f"Export checksum is not a file: '{hash_path}'"
        )

    # The checksum sidecar should contain only one SHA-256 digest.
    if hash_path.stat().st_size > 1024:
        raise ValueError(
            "Export checksum file is unexpectedly large."
        )

    expected_hash = hash_path.read_text(
        encoding="utf-8"
    ).strip()

    if (
        len(expected_hash) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in expected_hash
        )
    ):
        raise ValueError(
            "Export checksum contains an invalid SHA-256 digest."
        )

    actual_hash = _calculate_file_sha256(
        archive_path
    )

    if not secrets.compare_digest(
        actual_hash.lower(),
        expected_hash.lower()
    ):
        raise ValueError(
            "Export archive checksum verification failed."
        )

    # Read and validate export metadata before extracting anything.
    try:
        with tarfile.open(
            archive_path,
            "r:*"
        ) as tar:

            members = tar.getmembers()

            if not members:
                raise ValueError(
                    "Export archive is empty."
                )

            member_names = [
                member.name
                for member in members
            ]

            if len(member_names) != len(set(member_names)):
                raise ValueError(
                    "Export archive contains duplicate entries."
                )

            export_members = [
                member
                for member in members
                if member.name == "export.json"
            ]

            if len(export_members) != 1:
                raise ValueError(
                    "Export archive must contain exactly one export.json."
                )

            export_member = export_members[0]

            if not export_member.isfile():
                raise ValueError(
                    "Export metadata entry is not a regular file."
                )

            # Prevent unreasonable metadata files from being loaded into memory.
            if export_member.size > 64 * 1024:
                raise ValueError(
                    "Export metadata file is unexpectedly large."
                )

            export_file = tar.extractfile(
                export_member
            )

            if export_file is None:
                raise ValueError(
                    "Export metadata file is invalid."
                )

            try:
                export_data = json.loads(
                    export_file.read().decode("utf-8")
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError
            ) as e:
                raise ValueError(
                    "Export metadata contains invalid JSON."
                ) from e

    except tarfile.TarError as e:
        raise ValueError(
            "Export archive is not a valid TAR archive."
        ) from e

    if not isinstance(export_data, dict):
        raise ValueError(
            "Export metadata must contain a JSON object."
        )

    # Validate export format identifier.
    if (
        export_data.get("format")
        != vault_config.VAULT_EXPORT_FORMAT
    ):
        raise ValueError(
            "Unsupported export format."
        )

    # Validate export format version.
    export_version = export_data.get(
        "version"
    )

    if type(export_version) is not int:
        raise ValueError(
            "Export contains invalid export version."
        )

    if (
        export_version
        != vault_config.VAULT_EXPORT_VERSION
    ):
        raise ValueError(
            f"Unsupported export version: {export_version}."
        )

    # Validate vault format version.
    vault_format_version = export_data.get(
        "vault_format_version"
    )

    if type(vault_format_version) is not int:
        raise ValueError(
            "Export contains invalid vault format version."
        )

    if (
        vault_format_version
        != vault_config.VAULT_FORMAT_VERSION
    ):
        raise ValueError(
            f"Unsupported vault format version: "
            f"{vault_format_version}."
        )

    # Validate random vault identifier.
    vault_id = export_data.get(
        "vault_id"
    )

    if not isinstance(vault_id, str) or not vault_id:
        raise ValueError(
            "Export contains invalid vault_id."
        )

    try:
        vault_id_bytes = bytes.fromhex(
            vault_id
        )
    except ValueError as e:
        raise ValueError(
            "Export contains invalid vault_id."
        ) from e

    if not vault_id_bytes:
        raise ValueError(
            "Export contains invalid vault_id."
        )

    created_at = export_data.get(
        "created_at"
    )

    if not isinstance(created_at, str) or not created_at:
        raise ValueError(
            "Export contains invalid creation timestamp."
        )

    # Validate the complete TAR structure before extraction.
    try:
        with tarfile.open(
            archive_path,
            "r:*"
        ) as tar:

            members = tar.getmembers()

            expected_root = vault_id

            required_entries = {
                expected_root,
                f"{expected_root}/key.enc",
                f"{expected_root}/manifest.enc",
                f"{expected_root}/data",
            }

            archive_entries = {
                member.name
                for member in members
            }

            if not required_entries.issubset(
                archive_entries
            ):
                raise ValueError(
                    "Export archive is missing required vault files."
                )

            for member in members:

                # export.json is the only allowed top-level metadata file.
                if member.name == "export.json":
                    if not member.isfile():
                        raise ValueError(
                            "export.json must be a regular file."
                        )
                    continue

                # Backslashes could become path separators on Windows.
                if "\\" in member.name:
                    raise ValueError(
                        f"Unsafe TAR path: '{member.name}'."
                    )

                raw_parts = member.name.split("/")

                if any(
                    part in ("", ".", "..")
                    for part in raw_parts
                ):
                    raise ValueError(
                        f"Unsafe TAR path: '{member.name}'."
                    )

                path = PurePosixPath(
                    member.name
                )

                if path.is_absolute():
                    raise ValueError(
                        f"Absolute TAR path is not allowed: "
                        f"'{member.name}'."
                    )

                parts = path.parts

                # Everything except export.json must be stored inside
                # the vault_id directory.
                if (
                    not parts
                    or parts[0] != expected_root
                ):
                    raise ValueError(
                        f"Unexpected TAR entry: '{member.name}'."
                    )

                # Reject symbolic links, hard links, devices, FIFOs and
                # any other unsupported TAR entry type.
                if not (
                    member.isfile()
                    or member.isdir()
                ):
                    raise ValueError(
                        f"Unsupported TAR entry type: "
                        f"'{member.name}'."
                    )

                # Root vault directory.
                if len(parts) == 1:
                    if not member.isdir():
                        raise ValueError(
                            "Vault root entry must be a directory."
                        )
                    continue

                # key.enc and manifest.enc.
                if (
                    len(parts) == 2
                    and parts[1] in (
                        "key.enc",
                        "manifest.enc"
                    )
                ):
                    if not member.isfile():
                        raise ValueError(
                            f"Vault entry must be a regular file: "
                            f"'{member.name}'."
                        )
                    continue

                # data directory.
                if (
                    len(parts) == 2
                    and parts[1] == "data"
                ):
                    if not member.isdir():
                        raise ValueError(
                            "Vault data entry must be a directory."
                        )
                    continue

                # Encrypted file blobs may exist only directly inside data/.
                if (
                    len(parts) == 3
                    and parts[1] == "data"
                ):
                    if not member.isfile():
                        raise ValueError(
                            f"Encrypted vault blob must be a regular file: "
                            f"'{member.name}'."
                        )

                    if not parts[2].endswith(".enc"):
                        raise ValueError(
                            f"Invalid encrypted vault blob: "
                            f"'{member.name}'."
                        )

                    continue

                raise ValueError(
                    f"Unexpected TAR entry: '{member.name}'."
                )

    except tarfile.TarError as e:
        raise ValueError(
            "Export archive structure could not be validated."
        ) from e

    # Prevent overwriting an already imported vault.
    final_vault_path = (
        VAULT_ROOT
        / vault_id
    )

    if final_vault_path.exists():
        raise FileExistsError(
            f"Vault '{vault_id}' already exists."
        )

    VAULT_ROOT.mkdir(
        parents=True,
        exist_ok=True
    )

    # Extract inside VAULT_ROOT so the final rename remains on the same
    # filesystem and can be performed atomically.
    with tempfile.TemporaryDirectory(
        prefix=".vault-import-",
        dir=VAULT_ROOT
    ) as temporary_directory:

        staging_root = Path(
            temporary_directory
        )

        try:
            # Extract only already validated regular files and directories.
            with tarfile.open(
                archive_path,
                "r:*"
            ) as tar:

                for member in tar.getmembers():

                    if member.name == "export.json":
                        continue

                    parts = PurePosixPath(
                        member.name
                    ).parts

                    target_path = staging_root.joinpath(
                        *parts
                    )

                    if member.isdir():
                        target_path.mkdir(
                            parents=True,
                            exist_ok=True
                        )
                        continue

                    target_path.parent.mkdir(
                        parents=True,
                        exist_ok=True
                    )

                    source_file = tar.extractfile(
                        member
                    )

                    if source_file is None:
                        raise ValueError(
                            f"Could not read TAR entry: "
                            f"'{member.name}'."
                        )

                    with target_path.open(
                        "xb"
                    ) as output_file:
                        shutil.copyfileobj(
                            source_file,
                            output_file,
                            length=4 * 1024 * 1024
                        )

        except tarfile.TarError as e:
            raise ValueError(
                "Export archive extraction failed."
            ) from e

        staged_vault_path = (
            staging_root
            / vault_id
        )

        if (
            not staged_vault_path.exists()
            or not staged_vault_path.is_dir()
        ):
            raise ValueError(
                "Imported vault directory is missing."
            )

        # Unlock key.enc and authenticate manifest.enc.
        master_key, real_vault_id, manifest = _unlock_vault_path(
            staged_vault_path,
            password
        )

        real_vault_id_hex = real_vault_id.hex()

        # The external metadata, key file, manifest and folder must all
        # reference the same random vault identifier.
        if real_vault_id_hex != vault_id:
            raise ValueError(
                "Export vault_id does not match encrypted key metadata."
            )

        if manifest.vault_id != real_vault_id_hex:
            raise ValueError(
                "Manifest vault_id does not match encrypted key metadata."
            )

        if (
            manifest.format_version
            != vault_format_version
        ):
            raise ValueError(
                "Vault format version does not match export metadata."
            )

        # Verify the complete imported vault before publishing it.
        _verify_vault_path(
            staged_vault_path,
            master_key,
            real_vault_id,
            manifest
        )

        # Avoid creating another vault with the same decrypted name and password.
        try:
            _find_vault(
                manifest.vault_name,
                password
            )
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(
                f"Vault '{manifest.vault_name}' already exists."
            )

        # Check again immediately before publishing the imported vault.
        if final_vault_path.exists():
            raise FileExistsError(
                f"Vault '{vault_id}' already exists."
            )

        # Atomically publish the fully verified vault.
        staged_vault_path.rename(
            final_vault_path
        )

    return final_vault_path

def create_vault(vault_name: str, password: str, source: str) -> bool:
    """
    Create a new encrypted vault from the selected source folder.

    The function scans the source folder, generates a random master key,
    encrypts every file separately and finally creates an authenticated
    encrypted manifest describing the complete vault contents.

    The physical vault directory is named using random vault_id instead of
    SHA-256(vault_name). This prevents offline guessing of vault names from
    directory names.

    Args:
        vault_name (str): Name of the vault to create.
        password (str): Password used only to protect the random master key.
        source (str): Path to the source folder.

    Returns:
        bool: True if the vault was created successfully,
              False if an error occurred.
    """

    vault_path = None
    vault_created = False

    try:
        # Scan the source folder and create entries for files and directories.
        files, directories = _scan_source(source)

        # Check for an already existing vault that can be unlocked using the
        # same name and password. Fully encrypted names prevent global duplicate
        # checks without knowing passwords of other vaults.
        try:
            _find_vault(vault_name, password)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(
                f"Vault '{vault_name}' already exists."
            )

        # Generate one random vault identifier and one random master key.
        vault_id = crypto.generate_vault_id()
        master_key = crypto.generate_master_key()

        # Random vault_id becomes the physical directory name.
        VAULT_ROOT.mkdir(parents=True, exist_ok=True)
        vault_path = VAULT_ROOT / vault_id.hex()

        # Collision is extremely unlikely, but never overwrite an existing vault.
        while vault_path.exists():
            vault_id = crypto.generate_vault_id()
            vault_path = VAULT_ROOT / vault_id.hex()

        # Create the main vault directory.
        vault_path.mkdir(parents=True)
        vault_created = True

        # Create directory for separately encrypted vault files.
        data_path = vault_path / "data"
        data_path.mkdir()

        # Protect only the master key with the user password.
        # Changing the password later will not require re-encrypting file contents.
        crypto.save_master_key(
            vault_path / "key.enc",
            master_key,
            password,
            vault_id
        )

        # Convert source path to Path so it can be combined with file paths.
        source_path = Path(source)

        # Encrypt every source file separately.
        for file in files:
            plaintext_hash = crypto.encrypt_file(
                source_path / file.path,
                data_path / file.storage_name,
                master_key,
                vault_id,
                bytes.fromhex(file.file_id),
                file.size
            )

            # Store plaintext SHA-256 only inside encrypted manifest.
            file.sha256 = plaintext_hash

        # Create the encrypted manifest after every file hash is known.
        mf.create_manifest(
            vault_name,
            vault_path,
            master_key,
            vault_id,
            files,
            directories
        )

        return True

    except Exception as e:

        # Remove incomplete vault only if it was created
        # during the current create_vault operation.
        if (
            vault_created
            and vault_path is not None
            and vault_path.exists()
        ):
            shutil.rmtree(vault_path)

        print(f"Error creating vault: {e}")
        return False


def list_vaults(
    password: str | None = None
) -> list[vault_config.VaultListEntry]:
    """
    List stored vault directories without exposing encrypted names by default.

    Without a password only random vault identifiers are returned. When a
    password is provided, every candidate is authenticated and vault names are
    shown only for vaults that can be successfully unlocked with that password.

    Args:
        password (str | None): Optional password used to unlock vault names.

    Returns:
        list[vault_config.VaultListEntry]: Stored vault identifiers and,
        when possible, decrypted names.
    """

    entries = []

    for vault_path in _iter_vault_paths():
        vault_id = vault_path.name
        vault_name = None
        unlocked = False

        if password is not None:
            try:
                _, real_vault_id, manifest = _unlock_vault_path(
                    vault_path,
                    password
                )

                vault_id = real_vault_id.hex()
                vault_name = manifest.vault_name
                unlocked = True

            except (FileNotFoundError, ValueError):
                # Keep the vault name hidden when this password cannot unlock it.
                pass

        entries.append(
            vault_config.VaultListEntry(
                vault_id=vault_id,
                vault_name=vault_name,
                unlocked=unlocked
            )
        )

    return entries


def open_vault(
    vault_name: str,
    password: str
) -> vault_config.VaultManifest:
    """
    Open an existing vault and return its decrypted manifest.

    The vault directory cannot be located from the encrypted name directly.
    Candidate vaults are authenticated until the requested decrypted name is
    found. File contents remain encrypted until explicitly extracted.

    Args:
        vault_name (str): Name of the vault to open.
        password (str): Password used to unlock the vault master key.

    Returns:
        vault_config.VaultManifest: Decrypted and validated vault manifest.

    Raises:
        FileNotFoundError: If the vault cannot be found or unlocked.
        ValueError: If more than one matching vault exists.
    """

    _, _, _, manifest = _find_vault(
        vault_name,
        password
    )

    return manifest


def add_file(
    vault_name: str,
    password: str,
    source: str,
    file_path: str | None = None
) -> vault_config.FileEntry:
    """
    Add one file to an existing vault without rebuilding other encrypted files.

    The source file receives a new random file_id and storage name. Only this
    file is encrypted, then the authenticated manifest is updated atomically.

    Args:
        vault_name (str): Name of the vault.
        password (str): Password used to unlock the vault.
        source (str): Path to the plaintext file being added.
        file_path (str | None): Optional path visible inside the vault.
                               Defaults to the source file name.

    Returns:
        vault_config.FileEntry: Metadata of the newly added file.

    Raises:
        FileNotFoundError: If source or vault cannot be found.
        ValueError: If source is not a file or target path already exists.
    """

    source_path = Path(source)

    if not source_path.exists():
        raise FileNotFoundError(
            f"Source file '{source}' does not exist."
        )

    if not source_path.is_file():
        raise ValueError(
            f"Source '{source}' is not a file."
        )

    # Use original source name unless a custom logical vault path is provided.
    target_path = _normalize_vault_file_path(
        file_path if file_path is not None else source_path.name
    )

    vault_path, master_key, vault_id, manifest = _find_vault(
        vault_name,
        password
    )

    if any(file.path == target_path for file in manifest.files):
        raise FileExistsError(
            f"File '{target_path}' already exists in vault."
        )

    stat = source_path.stat()
    file_id = crypto.generate_file_id()
    storage_name = f"{secrets.token_hex(16)}.enc"

    file_entry = vault_config.FileEntry(
        path=target_path,
        file_id=file_id.hex(),
        storage_name=storage_name,
        sha256="",
        size=stat.st_size,
        date_created=_format_timestamp(stat.st_ctime),
        date_modified=_format_timestamp(stat.st_mtime)
    )

    encrypted_path = vault_path / "data" / storage_name

    try:
        # Encrypt only the new file and calculate plaintext SHA-256 in one pass.
        file_entry.sha256 = crypto.encrypt_file(
            source_path,
            encrypted_path,
            master_key,
            vault_id,
            file_id,
            file_entry.size
        )

        # Add metadata only after encrypted file creation succeeds.
        manifest.files.append(file_entry)
        _refresh_directory_metadata(manifest)

        # Atomically publish the updated encrypted manifest.
        mf.save_manifest(
            manifest,
            vault_path,
            master_key,
            vault_id
        )

    except Exception:
        # Remove the newly encrypted blob if manifest update fails.
        if encrypted_path.exists():
            encrypted_path.unlink()
        raise

    return file_entry


def remove_file(
    vault_name: str,
    password: str,
    file_path: str
) -> None:
    """
    Remove one file from a vault without touching unrelated encrypted files.

    The encrypted blob is first moved to a temporary name. The manifest is
    updated next. If manifest saving fails, the blob is restored so the vault
    remains consistent.

    Args:
        vault_name (str): Name of the vault.
        password (str): Password used to unlock the vault.
        file_path (str): Logical path of the file inside the vault.

    Raises:
        FileNotFoundError: If vault, manifest entry or encrypted blob is missing.
    """

    normalized_path = _normalize_vault_file_path(file_path)

    vault_path, master_key, vault_id, manifest = _find_vault(
        vault_name,
        password
    )

    file_entry = next(
        (
            file
            for file in manifest.files
            if file.path == normalized_path
        ),
        None
    )

    if file_entry is None:
        raise FileNotFoundError(
            f"File '{file_path}' does not exist in vault."
        )

    encrypted_path = vault_path / "data" / file_entry.storage_name

    if not encrypted_path.exists():
        raise FileNotFoundError(
            f"Encrypted data for '{file_path}' does not exist."
        )

    # Move the blob instead of deleting immediately so failure can be rolled back.
    removed_path = encrypted_path.with_name(
        f".{encrypted_path.name}.{secrets.token_hex(8)}.remove"
    )
    encrypted_path.replace(removed_path)

    try:
        manifest.files.remove(file_entry)
        _refresh_directory_metadata(manifest)

        mf.save_manifest(
            manifest,
            vault_path,
            master_key,
            vault_id
        )

    except Exception:
        # Restore encrypted data if manifest update did not complete.
        if removed_path.exists():
            removed_path.replace(encrypted_path)
        raise

    # Delete encrypted data only after the new manifest is safely stored.
    removed_path.unlink()


def rename_file(
    vault_name: str,
    password: str,
    file_path: str,
    new_path: str
) -> vault_config.FileEntry:
    """
    Rename or move one logical file by changing only encrypted manifest metadata.

    File contents are not decrypted or re-encrypted because the original path
    is metadata protected by manifest authentication, not part of the file key.

    Args:
        vault_name (str): Name of the vault.
        password (str): Password used to unlock the vault.
        file_path (str): Existing logical path inside the vault.
        new_path (str): New logical path inside the vault.

    Returns:
        vault_config.FileEntry: Updated file metadata.

    Raises:
        FileNotFoundError: If the original file does not exist.
        FileExistsError: If another file already uses the new path.
    """

    old_path = _normalize_vault_file_path(file_path)
    normalized_new_path = _normalize_vault_file_path(new_path)

    vault_path, master_key, vault_id, manifest = _find_vault(
        vault_name,
        password
    )

    file_entry = next(
        (
            file
            for file in manifest.files
            if file.path == old_path
        ),
        None
    )

    if file_entry is None:
        raise FileNotFoundError(
            f"File '{file_path}' does not exist in vault."
        )

    if any(
        file.path == normalized_new_path
        and file is not file_entry
        for file in manifest.files
    ):
        raise FileExistsError(
            f"File '{normalized_new_path}' already exists in vault."
        )

    previous_path = file_entry.path

    try:
        # Only authenticated manifest metadata changes during rename.
        file_entry.path = normalized_new_path
        _refresh_directory_metadata(manifest)

        mf.save_manifest(
            manifest,
            vault_path,
            master_key,
            vault_id
        )

    except Exception:
        # Restore in-memory state if manifest update fails.
        file_entry.path = previous_path
        _refresh_directory_metadata(manifest)
        raise

    return file_entry



def change_password(
    vault_name: str,
    current_password: str,
    new_password: str
) -> None:
    """
    Change the vault password without re-encrypting stored file data.

    The current password is used to unlock the existing random master key.
    Only key.enc is then recreated with a fresh Scrypt salt, fresh AES-GCM
    nonce and the new password. manifest.enc and data/*.enc remain unchanged.

    Args:
        vault_name (str): Name of the vault.
        current_password (str): Password currently protecting the vault.
        new_password (str): New password used to protect the same master key.

    Raises:
        FileNotFoundError: If the vault cannot be found or unlocked.
        ValueError: If the new password is empty or the vault is inconsistent.
    """

    if not new_password:
        raise ValueError("New password cannot be empty.")

    # Unlock the vault first so an invalid current password changes nothing.
    vault_path, master_key, vault_id, _ = _find_vault(
        vault_name,
        current_password
    )

    key_path = vault_path / "key.enc"
    temp_path = key_path.with_name(
        f".{key_path.name}.{secrets.token_hex(8)}.tmp"
    )

    try:
        # Re-wrap only the existing master key using the new password.
        crypto.save_master_key(
            temp_path,
            master_key,
            new_password,
            vault_id
        )

        # Verify the newly created key file before replacing the old one.
        verified_master_key, verified_vault_id = crypto.load_master_key(
            temp_path,
            new_password
        )

        if verified_master_key != master_key:
            raise ValueError("Re-wrapped master key verification failed.")

        if verified_vault_id != vault_id:
            raise ValueError("Re-wrapped vault_id verification failed.")

        # Replace key.enc atomically only after the new file is verified.
        temp_path.replace(key_path)

    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise


def verify_vault(
    vault_name: str,
    password: str
) -> vault_config.VaultVerifyResult:
    """
    Verify the complete encrypted vault without extracting plaintext files.

    The vault is unlocked and its authenticated manifest is loaded first.
    Shared path-based verification then validates every encrypted blob, logical
    path, directory size and manifest-to-data relationship.

    Args:
        vault_name (str): Name of the vault to verify.
        password (str): Password used to unlock the vault.

    Returns:
        vault_config.VaultVerifyResult: Summary of successfully verified data.

    Raises:
        FileNotFoundError: If the vault or an encrypted file is missing.
        ValueError: If metadata, file layout or cryptographic verification fails.
    """

    vault_path, master_key, vault_id, manifest = _find_vault(
        vault_name,
        password
    )

    return _verify_vault_path(
        vault_path,
        master_key,
        vault_id,
        manifest
    )

def extract_file(
    vault_name: str,
    password: str,
    file_path: str,
    destination: str
) -> Path:
    """
    Extract and verify a single file from an encrypted vault.

    The function unlocks the vault master key, loads the authenticated
    manifest, finds the selected file and decrypts only its encrypted blob.
    File identity, chunk order, final size and SHA-256 are verified before
    plaintext is published at the requested destination.

    Args:
        vault_name (str): Name of the vault.
        password (str): Password used to unlock the vault master key.
        file_path (str): Path of the file inside the vault.
        destination (str): Folder where the file will be extracted.

    Returns:
        Path: Path to the extracted and verified file.

    Raises:
        FileNotFoundError: If the vault or requested file does not exist.
        ValueError: If any vault or file integrity check fails.
    """

    normalized_path = _normalize_vault_file_path(file_path)

    vault_path, master_key, vault_id, manifest = _find_vault(
        vault_name,
        password
    )

    # Find requested file in the manifest.
    file_entry = next(
        (
            file
            for file in manifest.files
            if file.path == normalized_path
        ),
        None
    )

    # Stop if the requested file is not stored in the vault.
    if file_entry is None:
        raise FileNotFoundError(
            f"File '{file_path}' does not exist in vault."
        )

    # Build path to the encrypted file using its random storage name.
    encrypted_path = (
        vault_path
        / "data"
        / file_entry.storage_name
    )

    # Restore the original file path inside the destination directory.
    output_path = (
        Path(destination)
        / Path(*PurePosixPath(file_entry.path).parts)
    )

    # Create destination directories if needed.
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Decrypt and verify only requested file.
    crypto.decrypt_file(
        encrypted_path,
        output_path,
        master_key,
        vault_id,
        bytes.fromhex(file_entry.file_id),
        file_entry.size,
        file_entry.sha256
    )

    return output_path


def _scan_source(
    source: str
) -> tuple[list[vault_config.FileEntry], list[vault_config.DirectoryEntry]]:
    """
    Scan the source folder and build metadata entries for the manifest.

    Every file receives a random file_id used by cryptographic integrity
    checks and a separate random storage name used inside the data directory.
    SHA-256 is filled later while the file is being encrypted, avoiding an
    unnecessary second read of potentially large source files.

    Args:
        source (str): Path to the source folder to scan.

    Returns:
        tuple: Two lists containing FileEntry and DirectoryEntry objects.

    Raises:
        FileNotFoundError: If the source path does not exist.
        NotADirectoryError: If the source path is not a directory.
    """

    # Convert the provided source path to a Path object.
    source_path = Path(source)

    # Check if the source folder exists.
    if not source_path.exists():
        raise FileNotFoundError(
            f"Source folder '{source}' does not exist."
        )

    # The vault can only be created from a directory.
    if not source_path.is_dir():
        raise NotADirectoryError(
            f"Source '{source}' is not a directory."
        )

    files = []
    directories = []

    # Scan every file and directory inside the source folder recursively.
    for item in source_path.rglob("*"):
        # Store paths in POSIX format so the manifest is system independent.
        relative_path = item.relative_to(source_path).as_posix()

        # Read filesystem metadata for the current item.
        stat = item.stat()

        date_created = _format_timestamp(stat.st_ctime)
        date_modified = _format_timestamp(stat.st_mtime)

        if item.is_file():

            # Generate independent random identifiers for cryptographic
            # file identity and the physical encrypted storage name.
            file_id = crypto.generate_file_id()
            storage_name = f"{secrets.token_hex(16)}.enc"

            # Create metadata entry for a file.
            files.append(
                vault_config.FileEntry(
                    path=relative_path,
                    file_id=file_id.hex(),
                    storage_name=storage_name,
                    sha256="",
                    size=stat.st_size,
                    date_created=date_created,
                    date_modified=date_modified
                )
            )

        elif item.is_dir():

            # Calculate total size of all files inside this directory.
            directory_size = sum(
                file.stat().st_size
                for file in item.rglob("*")
                if file.is_file()
            )

            # Create metadata entry for a directory.
            directories.append(
                vault_config.DirectoryEntry(
                    path=relative_path,
                    size=directory_size,
                    date_created=date_created,
                    date_modified=date_modified
                )
            )

    return files, directories
