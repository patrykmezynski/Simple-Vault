#standard library imports
from pathlib import Path, PurePosixPath
from hashlib import sha256
from datetime import datetime

import secrets
import shutil

#local imports
from src import vault_config
from src import crypto
from src import manifest as mf


VAULT_ROOT = Path("vaults")


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

    key.enc and manifest.enc are authenticated while the vault is unlocked.
    Every encrypted data blob is then decrypted chunk by chunk in memory and
    checked against vault_id, file_id, size, AES-GCM tags and plaintext SHA-256.
    The data directory must contain exactly the blobs referenced by manifest.

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
            + ")."
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


def test():
    """Run create, open, add, rename, remove, extract, verify and password tests."""

    vault_name = f"TestVault-{secrets.token_hex(4)}"
    password = "password123"
    output_path = Path("test_output")
    vault_path = None

    if output_path.exists(): # Remove previous extraction output.
        shutil.rmtree(output_path)

    try: # Testing _scan_source
        files, directories = _scan_source("test")

        assert isinstance(files, list)
        assert isinstance(directories, list)

        print("[PASSED] _scan_source")

    except Exception as e:
        print(
            f"[FAILED] _scan_source: Error occurred: {e}"
        )

    try: # Testing create_vault
        result = create_vault(
            vault_name,
            password,
            "test"
        )

        assert result is True

        vault_path, _, _, _ = _find_vault(
            vault_name,
            password
        )

        assert (vault_path / "key.enc").exists()
        assert (vault_path / "manifest.enc").exists()
        assert (vault_path / "data").exists()
        assert vault_path.name != sha256(
            vault_name.encode("utf-8")
        ).hexdigest()

        print("[PASSED] create_vault")

    except Exception as e:
        print(
            f"[FAILED] create_vault: Error occurred: {e}"
        )

    try: # Testing open_vault
        result = open_vault(
            vault_name,
            password
        )

        assert isinstance(result, vault_config.VaultManifest)
        assert result.vault_name == vault_name
        assert result.file_count > 0
        assert all(file.file_id for file in result.files)
        assert all(len(file.sha256) == 64 for file in result.files)

        print("[PASSED] open_vault")

    except Exception as e:
        print(
            f"[FAILED] open_vault: Error occurred: {e}"
        )

    try: # Testing add_file
        added = add_file(
            vault_name,
            password,
            "test/test.txt",
            "added/test_copy.txt"
        )

        manifest = open_vault(vault_name, password)

        assert added.path == "added/test_copy.txt"
        assert any(
            file.path == "added/test_copy.txt"
            for file in manifest.files
        )

        print("[PASSED] add_file")

    except Exception as e:
        print(
            f"[FAILED] add_file: Error occurred: {e}"
        )

    try: # Testing rename_file
        renamed = rename_file(
            vault_name,
            password,
            "added/test_copy.txt",
            "renamed/test_copy.txt"
        )

        manifest = open_vault(vault_name, password)

        assert renamed.path == "renamed/test_copy.txt"
        assert any(
            file.path == "renamed/test_copy.txt"
            for file in manifest.files
        )

        print("[PASSED] rename_file")

    except Exception as e:
        print(
            f"[FAILED] rename_file: Error occurred: {e}"
        )

    try: # Testing remove_file
        remove_file(
            vault_name,
            password,
            "renamed/test_copy.txt"
        )

        manifest = open_vault(vault_name, password)

        assert not any(
            file.path == "renamed/test_copy.txt"
            for file in manifest.files
        )

        print("[PASSED] remove_file")

    except Exception as e:
        print(
            f"[FAILED] remove_file: Error occurred: {e}"
        )

    try: # Testing extract_file
        manifest = open_vault(
            vault_name,
            password
        )

        if manifest.files:
            selected_file = manifest.files[0]

            extracted_path = extract_file(
                vault_name,
                password,
                selected_file.path,
                str(output_path)
            )

            assert extracted_path.exists()
            assert sha256(
                extracted_path.read_bytes()
            ).hexdigest() == selected_file.sha256

        print("[PASSED] extract_file")

    except Exception as e:
        print(
            f"[FAILED] extract_file: Error occurred: {e}"
        )

    try: # Testing verify_vault
        verification = verify_vault(
            vault_name,
            password
        )

        assert isinstance(
            verification,
            vault_config.VaultVerifyResult
        )
        assert verification.vault_name == vault_name
        assert verification.file_count > 0

        print("[PASSED] verify_vault")

    except Exception as e:
        print(
            f"[FAILED] verify_vault: Error occurred: {e}"
        )

    try: # Testing change_password
        new_password = "password456"

        change_password(
            vault_name,
            password,
            new_password
        )

        # Old password must no longer unlock the vault.
        try:
            open_vault(vault_name, password)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError(
                "Old password still unlocks the vault."
            )

        manifest = open_vault(
            vault_name,
            new_password
        )

        assert manifest.vault_name == vault_name

        password = new_password

        print("[PASSED] change_password")

    except Exception as e:
        print(
            f"[FAILED] change_password: Error occurred: {e}"
        )

    try: # Testing list_vaults
        locked_entries = list_vaults()
        unlocked_entries = list_vaults(password)

        assert any(
            entry.vault_id == vault_path.name
            for entry in locked_entries
        )
        assert any(
            entry.vault_name == vault_name
            and entry.unlocked
            for entry in unlocked_entries
        )

        print("[PASSED] list_vaults")

    except Exception as e:
        print(
            f"[FAILED] list_vaults: Error occurred: {e}"
        )

    finally: # Clean up after test.
        if vault_path is not None and vault_path.exists():
            shutil.rmtree(vault_path)

        if output_path.exists():
            shutil.rmtree(output_path)
