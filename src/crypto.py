"""Cryptographic primitives and versioned binary formats used by Python Vault.

The module owns key derivation, key wrapping, authenticated manifest encryption,
and chunked authenticated file encryption and verification.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pathlib import Path
from hashlib import sha256

import hmac
import os
import secrets
import struct


# Current binary format version used by key, manifest and data files.
FORMAT_VERSION = 1

# Binary identifiers used to detect the type of encrypted file.
KEY_MAGIC = b"TVKY"
MANIFEST_MAGIC = b"TVMF"
DATA_MAGIC = b"TVDF"

# Encryption and identifier sizes.
MASTER_KEY_SIZE = 32
VAULT_ID_SIZE = 16
FILE_ID_SIZE = 16
SALT_SIZE = 16
NONCE_SIZE = 12
NONCE_PREFIX_SIZE = 4
GCM_TAG_SIZE = 16

# Files are processed in 4 MB chunks so large files are never fully loaded into RAM.
CHUNK_SIZE = 4 * 1024 * 1024
MAX_CHUNK_SIZE = CHUNK_SIZE

# Scrypt parameters used to turn the user password into a key-encryption key.
# N=2^17 intentionally makes offline password guessing more expensive.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

# Fixed binary field sizes used by the encrypted file format.
CHUNK_LENGTH_SIZE = 4
FILE_SIZE_FIELD_SIZE = 8
CHUNK_SIZE_FIELD_SIZE = 4
CHUNK_INDEX_SIZE = 8


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key-encryption key from the provided password.

    Scrypt makes password guessing expensive by requiring both CPU time and
    memory. The derived key is used only to encrypt or decrypt the random
    master key stored in key.enc.

    Args:
        password (str): Password provided by the user.
        salt (bytes): Random salt stored in key.enc.

    Returns:
        bytes: 32-byte key used to protect the master key.
    """

    # Validate salt size before using it in the KDF.
    if len(salt) != SALT_SIZE:
        raise ValueError("Invalid Scrypt salt size.")

    # Create password-based key derivation function.
    kdf = Scrypt(
        salt=salt,
        length=MASTER_KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    )

    return kdf.derive(password.encode("utf-8"))


def generate_master_key() -> bytes:
    """
    Generate a new random master key for one vault.

    Returns:
        bytes: Random 256-bit master key.
    """

    return os.urandom(MASTER_KEY_SIZE)


def generate_vault_id() -> bytes:
    """
    Generate a random identifier used to bind all parts of one vault.

    Returns:
        bytes: Random vault identifier.
    """

    return os.urandom(VAULT_ID_SIZE)


def generate_file_id() -> bytes:
    """
    Generate a random identifier used to bind one encrypted file.

    Returns:
        bytes: Random file identifier.
    """

    return os.urandom(FILE_ID_SIZE)


def _derive_subkey(
    master_key: bytes,
    info: bytes
) -> bytes:
    """
    Derive an independent encryption key from the vault master key.

    HKDF provides domain separation so the same master key is never used
    directly for the manifest and file contents.

    Args:
        master_key (bytes): Random master key belonging to the vault.
        info (bytes): Context describing what the derived key is used for.

    Returns:
        bytes: Independent 256-bit encryption key.
    """

    if len(master_key) != MASTER_KEY_SIZE:
        raise ValueError("Invalid master key size.")

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=MASTER_KEY_SIZE,
        salt=None,
        info=info
    )

    return kdf.derive(master_key)


def _derive_manifest_key(
    master_key: bytes,
    vault_id: bytes
) -> bytes:
    """Derive a key used only for manifest encryption."""

    _validate_vault_id(vault_id)

    return _derive_subkey(
        master_key,
        b"TVLT-MANIFEST-KEY-V1" + vault_id
    )


def _derive_file_key(
    master_key: bytes,
    vault_id: bytes,
    file_id: bytes
) -> bytes:
    """Derive a unique key used only for one encrypted file."""

    _validate_vault_id(vault_id)
    _validate_file_id(file_id)

    return _derive_subkey(
        master_key,
        b"TVLT-FILE-KEY-V1" + vault_id + file_id
    )


def save_master_key(
    key_path: Path,
    master_key: bytes,
    password: str,
    vault_id: bytes
) -> None:
    """
    Encrypt and save the vault master key using the user password.

    key.enc contains a versioned header, Scrypt salt, AES-GCM nonce and
    encrypted master key. The header is authenticated as AAD so changing
    the vault identifier or format version makes decryption fail.

    Args:
        key_path (Path): Destination path for key.enc.
        master_key (bytes): Random master key to protect.
        password (str): User password used to derive the wrapping key.
        vault_id (bytes): Random identifier belonging to this vault.
    """

    if len(master_key) != MASTER_KEY_SIZE:
        raise ValueError("Invalid master key size.")

    _validate_vault_id(vault_id)

    # Create password KDF salt and AES-GCM nonce.
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Derive a key used only to protect the random master key.
    wrapping_key = derive_key(password, salt)
    aes = AESGCM(wrapping_key)

    # Build authenticated file header.
    header = (
        KEY_MAGIC
        + bytes([FORMAT_VERSION])
        + vault_id
        + salt
    )

    # Encrypt the master key and authenticate the header.
    encrypted_master_key = aes.encrypt(
        nonce,
        master_key,
        header
    )

    # Save complete key file.
    with key_path.open("wb") as output:
        output.write(header)
        output.write(nonce)
        output.write(encrypted_master_key)


def load_master_key(
    key_path: Path,
    password: str
) -> tuple[bytes, bytes]:
    """
    Read and decrypt the vault master key using the user password.

    Args:
        key_path (Path): Path to key.enc.
        password (str): Password used to unlock the vault.

    Returns:
        tuple[bytes, bytes]: Decrypted master key and vault identifier.

    Raises:
        FileNotFoundError: If key.enc does not exist.
        ValueError: If the key file is invalid, unsupported or cannot be authenticated.
    """

    if not key_path.exists():
        raise FileNotFoundError(
            f"Vault key file does not exist: '{key_path}'."
        )

    data = key_path.read_bytes()

    # Calculate exact size expected for the fixed-size key file.
    header_size = (
        len(KEY_MAGIC)
        + 1
        + VAULT_ID_SIZE
        + SALT_SIZE
    )
    expected_size = (
        header_size
        + NONCE_SIZE
        + MASTER_KEY_SIZE
        + GCM_TAG_SIZE
    )

    if len(data) != expected_size:
        raise ValueError("Invalid or corrupted vault key file.")

    offset = 0

    # Read and validate key file magic.
    magic = data[offset:offset + len(KEY_MAGIC)]
    offset += len(KEY_MAGIC)

    if magic != KEY_MAGIC:
        raise ValueError("Invalid vault key file magic.")

    # Read and validate binary format version.
    version = data[offset]
    offset += 1

    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported vault key format version: {version}."
        )

    # Read vault identifier and Scrypt salt.
    vault_id = data[offset:offset + VAULT_ID_SIZE]
    offset += VAULT_ID_SIZE

    salt = data[offset:offset + SALT_SIZE]
    offset += SALT_SIZE

    # Read AES-GCM nonce and encrypted master key.
    nonce = data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    encrypted_master_key = data[offset:]

    # Rebuild exactly the same authenticated header used during encryption.
    header = data[:header_size]

    wrapping_key = derive_key(password, salt)
    aes = AESGCM(wrapping_key)

    try:
        master_key = aes.decrypt(
            nonce,
            encrypted_master_key,
            header
        )
    except InvalidTag as e:
        raise ValueError(
            "Invalid password or corrupted vault key."
        ) from e

    if len(master_key) != MASTER_KEY_SIZE:
        raise ValueError("Invalid decrypted master key size.")

    return master_key, vault_id


def encrypt_manifest(
    data: bytes,
    master_key: bytes,
    vault_id: bytes
) -> bytes:
    """
    Encrypt serialized manifest data using a manifest-specific key.

    Args:
        data (bytes): Serialized manifest JSON.
        master_key (bytes): Vault master key.
        vault_id (bytes): Random identifier belonging to this vault.

    Returns:
        bytes: Complete versioned encrypted manifest file.
    """

    _validate_vault_id(vault_id)

    manifest_key = _derive_manifest_key(
        master_key,
        vault_id
    )

    nonce = os.urandom(NONCE_SIZE)
    aes = AESGCM(manifest_key)

    # Header is authenticated but remains readable for format validation.
    header = (
        MANIFEST_MAGIC
        + bytes([FORMAT_VERSION])
        + vault_id
    )

    encrypted = aes.encrypt(
        nonce,
        data,
        header
    )

    return header + nonce + encrypted


def decrypt_manifest(
    data: bytes,
    master_key: bytes,
    expected_vault_id: bytes
) -> bytes:
    """
    Validate and decrypt a complete encrypted manifest file.

    Args:
        data (bytes): Bytes read from manifest.enc.
        master_key (bytes): Vault master key.
        expected_vault_id (bytes): Vault identifier read from key.enc.

    Returns:
        bytes: Decrypted manifest JSON.

    Raises:
        ValueError: If the manifest format or authentication is invalid.
    """

    _validate_vault_id(expected_vault_id)

    header_size = (
        len(MANIFEST_MAGIC)
        + 1
        + VAULT_ID_SIZE
    )
    minimum_size = header_size + NONCE_SIZE + GCM_TAG_SIZE

    if len(data) < minimum_size:
        raise ValueError("Invalid or corrupted manifest.")

    offset = 0

    # Read and validate manifest magic.
    magic = data[offset:offset + len(MANIFEST_MAGIC)]
    offset += len(MANIFEST_MAGIC)

    if magic != MANIFEST_MAGIC:
        raise ValueError("Invalid manifest file magic.")

    # Read and validate manifest format version.
    version = data[offset]
    offset += 1

    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported manifest format version: {version}."
        )

    vault_id = data[offset:offset + VAULT_ID_SIZE]
    offset += VAULT_ID_SIZE

    if not hmac.compare_digest(vault_id, expected_vault_id):
        raise ValueError("Manifest belongs to a different vault.")

    nonce = data[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE

    encrypted = data[offset:]
    header = data[:header_size]

    manifest_key = _derive_manifest_key(
        master_key,
        vault_id
    )
    aes = AESGCM(manifest_key)

    try:
        return aes.decrypt(
            nonce,
            encrypted,
            header
        )
    except InvalidTag as e:
        raise ValueError(
            "Invalid or corrupted vault manifest."
        ) from e


def encrypt_file(
    source_path: Path,
    output_path: Path,
    master_key: bytes,
    vault_id: bytes,
    file_id: bytes,
    expected_size: int
) -> str:
    """
    Encrypt one file in authenticated chunks without loading it fully into RAM.

    Every file receives a unique key derived from the vault master key and
    file_id. Chunk position and the complete file header are authenticated
    as AAD, preventing chunk reordering, duplication and cross-file swaps.

    Args:
        source_path (Path): Plaintext file to encrypt.
        output_path (Path): Destination encrypted file path.
        master_key (bytes): Vault master key.
        vault_id (bytes): Identifier belonging to this vault.
        file_id (bytes): Identifier belonging to this file.
        expected_size (int): File size recorded during source scanning.

    Returns:
        str: SHA-256 hash of the plaintext file as hexadecimal text.

    Raises:
        ValueError: If the source size changes while creating the vault.
    """

    _validate_vault_id(vault_id)
    _validate_file_id(file_id)

    if expected_size < 0:
        raise ValueError("Invalid expected file size.")

    # Check size before encryption to detect an obvious source change.
    current_size = source_path.stat().st_size
    if current_size != expected_size:
        raise ValueError(
            f"Source file changed before encryption: '{source_path}'."
        )

    file_key = _derive_file_key(
        master_key,
        vault_id,
        file_id
    )
    aes = AESGCM(file_key)

    # A random prefix plus chunk index guarantees a unique nonce per file key.
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)

    # Build fixed authenticated file header.
    header = (
        DATA_MAGIC
        + bytes([FORMAT_VERSION])
        + vault_id
        + file_id
        + struct.pack(">Q", expected_size)
        + struct.pack(">I", CHUNK_SIZE)
        + nonce_prefix
    )

    hasher = sha256()
    bytes_read = 0
    chunk_index = 0

    # Write to a temporary file so failed encryption never leaves a valid-looking blob.
    temp_path = output_path.with_name(
        f".{output_path.name}.{secrets.token_hex(8)}.tmp"
    )

    try:
        with source_path.open("rb") as source:
            with temp_path.open("wb") as output:

                # Save the versioned header before encrypted chunks.
                output.write(header)

                while True:
                    # Read only one chunk into memory.
                    chunk = source.read(CHUNK_SIZE)

                    if not chunk:
                        break

                    bytes_read += len(chunk)
                    hasher.update(chunk)

                    # Nonce is unique because chunk_index never repeats for this file key.
                    nonce = (
                        nonce_prefix
                        + chunk_index.to_bytes(CHUNK_INDEX_SIZE, "big")
                    )

                    # Bind chunk position and the complete file header to ciphertext.
                    aad = (
                        header
                        + chunk_index.to_bytes(CHUNK_INDEX_SIZE, "big")
                    )

                    encrypted_chunk = aes.encrypt(
                        nonce,
                        chunk,
                        aad
                    )

                    # Save encrypted chunk size followed by encrypted chunk data.
                    output.write(
                        struct.pack(">I", len(encrypted_chunk))
                    )
                    output.write(encrypted_chunk)

                    chunk_index += 1

        # Detect source changes that affected the amount of encrypted data.
        if bytes_read != expected_size:
            raise ValueError(
                f"Source file changed during encryption: '{source_path}'."
            )

        expected_chunks = _calculate_chunk_count(
            expected_size,
            CHUNK_SIZE
        )

        if chunk_index != expected_chunks:
            raise ValueError(
                f"Unexpected chunk count while encrypting '{source_path}'."
            )

        # Publish encrypted file only after the complete operation succeeds.
        temp_path.replace(output_path)

    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise

    return hasher.hexdigest()


def decrypt_file(
    source_path: Path,
    output_path: Path,
    master_key: bytes,
    expected_vault_id: bytes,
    expected_file_id: bytes,
    expected_size: int,
    expected_sha256: str
) -> None:
    """
    Validate and decrypt one encrypted file into the selected destination.

    The function verifies file identity, vault identity, chunk order, chunk
    authentication, final file size and SHA-256 before publishing plaintext.
    Decrypted data is first written to a temporary file so corrupted output
    is never left at the requested destination.

    Args:
        source_path (Path): Encrypted file stored inside the vault.
        output_path (Path): Destination for decrypted plaintext.
        master_key (bytes): Vault master key.
        expected_vault_id (bytes): Vault identifier read from key.enc.
        expected_file_id (bytes): File identifier stored in manifest.enc.
        expected_size (int): Original plaintext size stored in manifest.enc.
        expected_sha256 (str): Original plaintext SHA-256 stored in manifest.enc.

    Raises:
        ValueError: If any integrity, identity or format check fails.
    """

    _validate_vault_id(expected_vault_id)
    _validate_file_id(expected_file_id)

    if expected_size < 0:
        raise ValueError("Invalid expected file size.")

    try:
        expected_hash = bytes.fromhex(expected_sha256)
    except ValueError as e:
        raise ValueError("Invalid SHA-256 value stored in manifest.") from e

    if len(expected_hash) != sha256().digest_size:
        raise ValueError("Invalid SHA-256 length stored in manifest.")

    if not source_path.exists():
        raise FileNotFoundError(
            f"Encrypted file does not exist: '{source_path}'."
        )

    # Decrypt into a temporary file and publish it only after full verification.
    temp_path = output_path.with_name(
        f".{output_path.name}.{secrets.token_hex(8)}.tmp"
    )

    try:
        with source_path.open("rb") as source:

            # Read and validate fixed file header.
            header = _read_data_header(source)
            (
                vault_id,
                file_id,
                original_size,
                chunk_size,
                nonce_prefix
            ) = _parse_data_header(header)

            if not hmac.compare_digest(vault_id, expected_vault_id):
                raise ValueError("Encrypted file belongs to a different vault.")

            if not hmac.compare_digest(file_id, expected_file_id):
                raise ValueError("Encrypted file does not match manifest file_id.")

            if original_size != expected_size:
                raise ValueError("Encrypted file size does not match manifest.")

            if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
                raise ValueError("Invalid encrypted file chunk size.")

            file_key = _derive_file_key(
                master_key,
                vault_id,
                file_id
            )
            aes = AESGCM(file_key)

            expected_chunks = _calculate_chunk_count(
                original_size,
                chunk_size
            )

            hasher = sha256()
            bytes_written = 0

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            with temp_path.open("wb") as output:
                for chunk_index in range(expected_chunks):

                    # Read encrypted chunk length.
                    length_data = source.read(CHUNK_LENGTH_SIZE)
                    if len(length_data) != CHUNK_LENGTH_SIZE:
                        raise ValueError(
                            "Encrypted file ended before expected chunk length."
                        )

                    encrypted_size = struct.unpack(">I", length_data)[0]

                    # Calculate exact plaintext size expected for this chunk.
                    remaining = original_size - bytes_written
                    expected_plain_size = min(chunk_size, remaining)
                    expected_encrypted_size = (
                        expected_plain_size
                        + GCM_TAG_SIZE
                    )

                    if encrypted_size != expected_encrypted_size:
                        raise ValueError(
                            "Invalid encrypted chunk size."
                        )

                    encrypted_chunk = source.read(encrypted_size)
                    if len(encrypted_chunk) != encrypted_size:
                        raise ValueError(
                            "Encrypted file ended inside a chunk."
                        )

                    nonce = (
                        nonce_prefix
                        + chunk_index.to_bytes(CHUNK_INDEX_SIZE, "big")
                    )
                    aad = (
                        header
                        + chunk_index.to_bytes(CHUNK_INDEX_SIZE, "big")
                    )

                    try:
                        chunk = aes.decrypt(
                            nonce,
                            encrypted_chunk,
                            aad
                        )
                    except InvalidTag as e:
                        raise ValueError(
                            "Encrypted file authentication failed."
                        ) from e

                    if len(chunk) != expected_plain_size:
                        raise ValueError(
                            "Decrypted chunk size does not match file header."
                        )

                    hasher.update(chunk)
                    output.write(chunk)
                    bytes_written += len(chunk)

                # No bytes are allowed after the expected final chunk.
                if source.read(1) != b"":
                    raise ValueError(
                        "Encrypted file contains unexpected trailing data."
                    )

            # Verify complete plaintext size before publishing the file.
            if bytes_written != expected_size:
                raise ValueError(
                    "Decrypted file size does not match manifest."
                )

            # Verify whole-file SHA-256 stored inside authenticated manifest.
            actual_hash = hasher.digest()
            if not hmac.compare_digest(actual_hash, expected_hash):
                raise ValueError(
                    "Decrypted file SHA-256 does not match manifest."
                )

        # Publish plaintext only after every validation succeeds.
        temp_path.replace(output_path)

    except Exception:
        if temp_path.exists():
            temp_path.unlink()
        raise



def verify_file(
    source_path: Path,
    master_key: bytes,
    expected_vault_id: bytes,
    expected_file_id: bytes,
    expected_size: int,
    expected_sha256: str
) -> None:
    """
    Fully verify one encrypted file without writing plaintext to disk.

    The function performs the same identity, AES-GCM, chunk order, size and
    SHA-256 checks as decrypt_file(), but decrypted chunks are used only for
    verification and are discarded immediately afterwards.

    Args:
        source_path (Path): Encrypted file stored inside the vault.
        master_key (bytes): Vault master key.
        expected_vault_id (bytes): Vault identifier read from key.enc.
        expected_file_id (bytes): File identifier stored in manifest.enc.
        expected_size (int): Original plaintext size stored in manifest.enc.
        expected_sha256 (str): Original plaintext SHA-256 stored in manifest.enc.

    Raises:
        FileNotFoundError: If the encrypted file does not exist.
        ValueError: If any format, identity or integrity check fails.
    """

    _validate_vault_id(expected_vault_id)
    _validate_file_id(expected_file_id)

    if expected_size < 0:
        raise ValueError("Invalid expected file size.")

    try:
        expected_hash = bytes.fromhex(expected_sha256)
    except ValueError as e:
        raise ValueError("Invalid SHA-256 value stored in manifest.") from e

    if len(expected_hash) != sha256().digest_size:
        raise ValueError("Invalid SHA-256 length stored in manifest.")

    if not source_path.exists():
        raise FileNotFoundError(
            f"Encrypted file does not exist: '{source_path}'."
        )

    with source_path.open("rb") as source:

        # Read and validate fixed file header.
        header = _read_data_header(source)
        (
            vault_id,
            file_id,
            original_size,
            chunk_size,
            nonce_prefix
        ) = _parse_data_header(header)

        # Bind encrypted data to the expected vault and manifest entry.
        if not hmac.compare_digest(vault_id, expected_vault_id):
            raise ValueError("Encrypted file belongs to a different vault.")

        if not hmac.compare_digest(file_id, expected_file_id):
            raise ValueError("Encrypted file does not match manifest file_id.")

        if original_size != expected_size:
            raise ValueError("Encrypted file size does not match manifest.")

        if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
            raise ValueError("Invalid encrypted file chunk size.")

        # Recreate the file-specific key used during encryption.
        file_key = _derive_file_key(
            master_key,
            vault_id,
            file_id
        )
        aes = AESGCM(file_key)

        expected_chunks = _calculate_chunk_count(
            original_size,
            chunk_size
        )

        hasher = sha256()
        bytes_verified = 0

        for chunk_index in range(expected_chunks):

            # Read encrypted chunk length.
            length_data = source.read(CHUNK_LENGTH_SIZE)
            if len(length_data) != CHUNK_LENGTH_SIZE:
                raise ValueError(
                    "Encrypted file ended before expected chunk length."
                )

            encrypted_size = struct.unpack(">I", length_data)[0]

            # Calculate exact plaintext size expected for this chunk.
            remaining = original_size - bytes_verified
            expected_plain_size = min(chunk_size, remaining)
            expected_encrypted_size = (
                expected_plain_size
                + GCM_TAG_SIZE
            )

            if encrypted_size != expected_encrypted_size:
                raise ValueError("Invalid encrypted chunk size.")

            encrypted_chunk = source.read(encrypted_size)
            if len(encrypted_chunk) != encrypted_size:
                raise ValueError(
                    "Encrypted file ended inside a chunk."
                )

            # Rebuild nonce and AAD exactly as they were used for encryption.
            nonce = (
                nonce_prefix
                + chunk_index.to_bytes(CHUNK_INDEX_SIZE, "big")
            )
            aad = (
                header
                + chunk_index.to_bytes(CHUNK_INDEX_SIZE, "big")
            )

            try:
                chunk = aes.decrypt(
                    nonce,
                    encrypted_chunk,
                    aad
                )
            except InvalidTag as e:
                raise ValueError(
                    "Encrypted file authentication failed."
                ) from e

            if len(chunk) != expected_plain_size:
                raise ValueError(
                    "Decrypted chunk size does not match file header."
                )

            # Hash plaintext in memory, then discard the chunk.
            hasher.update(chunk)
            bytes_verified += len(chunk)

        # No bytes are allowed after the expected final chunk.
        if source.read(1) != b"":
            raise ValueError(
                "Encrypted file contains unexpected trailing data."
            )

    if bytes_verified != expected_size:
        raise ValueError(
            "Verified file size does not match manifest."
        )

    # Verify whole-file SHA-256 stored inside authenticated manifest.
    if not hmac.compare_digest(hasher.digest(), expected_hash):
        raise ValueError(
            "Verified file SHA-256 does not match manifest."
        )

def _read_data_header(source) -> bytes:
    """Read the fixed-size encrypted data file header."""

    header_size = (
        len(DATA_MAGIC)
        + 1
        + VAULT_ID_SIZE
        + FILE_ID_SIZE
        + FILE_SIZE_FIELD_SIZE
        + CHUNK_SIZE_FIELD_SIZE
        + NONCE_PREFIX_SIZE
    )

    header = source.read(header_size)

    if len(header) != header_size:
        raise ValueError("Invalid or truncated encrypted file header.")

    return header


def _parse_data_header(
    header: bytes
) -> tuple[bytes, bytes, int, int, bytes]:
    """Validate an encrypted data header and return its individual fields."""

    offset = 0

    magic = header[offset:offset + len(DATA_MAGIC)]
    offset += len(DATA_MAGIC)

    if magic != DATA_MAGIC:
        raise ValueError("Invalid encrypted file magic.")

    version = header[offset]
    offset += 1

    if version != FORMAT_VERSION:
        raise ValueError(
            f"Unsupported encrypted file format version: {version}."
        )

    vault_id = header[offset:offset + VAULT_ID_SIZE]
    offset += VAULT_ID_SIZE

    file_id = header[offset:offset + FILE_ID_SIZE]
    offset += FILE_ID_SIZE

    original_size = struct.unpack(
        ">Q",
        header[offset:offset + FILE_SIZE_FIELD_SIZE]
    )[0]
    offset += FILE_SIZE_FIELD_SIZE

    chunk_size = struct.unpack(
        ">I",
        header[offset:offset + CHUNK_SIZE_FIELD_SIZE]
    )[0]
    offset += CHUNK_SIZE_FIELD_SIZE

    nonce_prefix = header[offset:offset + NONCE_PREFIX_SIZE]

    return (
        vault_id,
        file_id,
        original_size,
        chunk_size,
        nonce_prefix
    )


def _calculate_chunk_count(
    file_size: int,
    chunk_size: int
) -> int:
    """Return the number of chunks required to store a file."""

    if file_size == 0:
        return 0

    return (file_size + chunk_size - 1) // chunk_size


def _validate_vault_id(vault_id: bytes) -> None:
    """Validate binary vault identifier size."""

    if len(vault_id) != VAULT_ID_SIZE:
        raise ValueError("Invalid vault_id size.")


def _validate_file_id(file_id: bytes) -> None:
    """Validate binary file identifier size."""

    if len(file_id) != FILE_ID_SIZE:
        raise ValueError("Invalid file_id size.")
