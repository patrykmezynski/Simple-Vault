"""Comprehensive functional and security regression tests for Python Vault.

The suite uses only temporary directories. No real vaults, exports or extracted
files in the project tree are modified. Run it with ``py test.py``.
"""

from __future__ import annotations

import copy
import io
import json
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from hashlib import sha256
from pathlib import Path

from click.testing import CliRunner

from src import cli
from src import vault as v
from src import vault_config


class VaultTestCase(unittest.TestCase):
    """Exercise core vault operations, import/export and hostile archive cases."""

    def setUp(self) -> None:
        """Create an isolated source tree and redirect the vault root."""

        self._temporary_directory = tempfile.TemporaryDirectory(
            prefix="python-vault-test-"
        )
        self.root = Path(self._temporary_directory.name)

        self.original_vault_root = v.VAULT_ROOT
        v.VAULT_ROOT = self.root / "vaults"

        self.source = self.root / "source"
        self.source.mkdir(parents=True)
        (self.source / "test.txt").write_text(
            "root test data",
            encoding="utf-8"
        )
        (self.source / "folder").mkdir()
        (self.source / "folder" / "nested.txt").write_text(
            "nested test data",
            encoding="utf-8"
        )

        self.output = self.root / "output"
        self.exports = self.root / "exports"
        self.vault_name = "TestVault"
        self.password = "password123"

    def tearDown(self) -> None:
        """Restore global configuration and remove all temporary test data."""

        v.VAULT_ROOT = self.original_vault_root
        self._temporary_directory.cleanup()

    def _create_vault(self) -> Path:
        """Create one valid vault and return its physical directory."""

        created = v.create_vault(
            self.vault_name,
            self.password,
            str(self.source)
        )
        self.assertTrue(created)

        vault_path, _, _, _ = v._find_vault(
            self.vault_name,
            self.password
        )
        return vault_path

    def _create_export(self) -> tuple[Path, Path]:
        """Create a vault and a valid export archive for import tests."""

        vault_path = self._create_vault()
        archive_path = v.export_vault(
            self.vault_name,
            self.password,
            str(self.exports)
        )
        return vault_path, archive_path

    @staticmethod
    def _read_archive_entries(
        archive_path: Path,
    ) -> list[tuple[tarfile.TarInfo, bytes | None]]:
        """Read TAR members and their file payloads into independent objects."""

        entries = []

        with tarfile.open(archive_path, "r:*") as tar:
            for member in tar.getmembers():
                member_copy = copy.copy(member)
                data = None

                if member.isfile():
                    source = tar.extractfile(member)
                    if source is None:
                        raise AssertionError(
                            f"Unable to read TAR member '{member.name}'."
                        )
                    data = source.read()

                entries.append((member_copy, data))

        return entries

    @staticmethod
    def _write_archive_entries(
        archive_path: Path,
        entries: list[tuple[tarfile.TarInfo, bytes | None]],
    ) -> None:
        """Replace an export TAR and regenerate its checksum sidecar."""

        temporary_path = archive_path.with_name(
            archive_path.name + ".rewrite"
        )

        with tarfile.open(temporary_path, "w") as tar:
            for member, data in entries:
                if member.isfile():
                    payload = data if data is not None else b""
                    member.size = len(payload)
                    tar.addfile(member, io.BytesIO(payload))
                else:
                    tar.addfile(member)

        temporary_path.replace(archive_path)

        hash_path = archive_path.with_suffix(
            archive_path.suffix + ".sha256"
        )
        hash_path.write_text(
            v._calculate_file_sha256(archive_path),
            encoding="utf-8"
        )

    def _replace_export_metadata(
        self,
        archive_path: Path,
        transform,
    ) -> None:
        """Rewrite export.json using a caller-provided dictionary transform."""

        entries = self._read_archive_entries(archive_path)
        updated_entries = []

        for member, data in entries:
            if member.name == "export.json":
                if data is None:
                    raise AssertionError("export.json has no payload.")

                metadata = json.loads(data.decode("utf-8"))
                transformed = transform(metadata)
                data = json.dumps(
                    transformed,
                    indent=4
                ).encode("utf-8")

            updated_entries.append((member, data))

        self._write_archive_entries(
            archive_path,
            updated_entries
        )

    def test_scan_source(self) -> None:
        """Source scanning should preserve portable relative paths."""

        files, directories = v._scan_source(str(self.source))

        file_paths = {entry.path for entry in files}
        directory_paths = {entry.path for entry in directories}

        self.assertEqual(
            file_paths,
            {"test.txt", "folder/nested.txt"}
        )
        self.assertIn("folder", directory_paths)
        self.assertTrue(all(entry.file_id for entry in files))
        self.assertTrue(all(entry.storage_name.endswith(".enc") for entry in files))

    def test_create_open_list_and_verify_vault(self) -> None:
        """A newly created vault should open, list and fully verify."""

        vault_path = self._create_vault()

        self.assertTrue((vault_path / "key.enc").is_file())
        self.assertTrue((vault_path / "manifest.enc").is_file())
        self.assertTrue((vault_path / "data").is_dir())
        self.assertNotEqual(
            vault_path.name,
            sha256(self.vault_name.encode("utf-8")).hexdigest()
        )

        manifest = v.open_vault(
            self.vault_name,
            self.password
        )
        self.assertEqual(manifest.vault_name, self.vault_name)
        self.assertEqual(manifest.file_count, 2)
        self.assertTrue(all(len(file.sha256) == 64 for file in manifest.files))

        locked_entries = v.list_vaults()
        unlocked_entries = v.list_vaults(self.password)

        self.assertTrue(any(
            entry.vault_id == vault_path.name
            and not entry.unlocked
            for entry in locked_entries
        ))
        self.assertTrue(any(
            entry.vault_name == self.vault_name
            and entry.unlocked
            for entry in unlocked_entries
        ))

        verification = v.verify_vault(
            self.vault_name,
            self.password
        )
        self.assertIsInstance(
            verification,
            vault_config.VaultVerifyResult
        )
        self.assertEqual(verification.file_count, 2)

    def test_add_rename_remove_and_extract_file(self) -> None:
        """Individual file operations should not require rebuilding the vault."""

        self._create_vault()
        extra_source = self.root / "extra.txt"
        extra_source.write_text("extra file", encoding="utf-8")

        added = v.add_file(
            self.vault_name,
            self.password,
            str(extra_source),
            "added/extra.txt"
        )
        self.assertEqual(added.path, "added/extra.txt")

        renamed = v.rename_file(
            self.vault_name,
            self.password,
            "added/extra.txt",
            "renamed/extra.txt"
        )
        self.assertEqual(renamed.path, "renamed/extra.txt")

        extracted_path = v.extract_file(
            self.vault_name,
            self.password,
            "renamed/extra.txt",
            str(self.output)
        )
        self.assertEqual(
            extracted_path.read_text(encoding="utf-8"),
            "extra file"
        )

        v.remove_file(
            self.vault_name,
            self.password,
            "renamed/extra.txt"
        )

        manifest = v.open_vault(
            self.vault_name,
            self.password
        )
        self.assertFalse(any(
            file.path == "renamed/extra.txt"
            for file in manifest.files
        ))

    def test_change_password_rewraps_existing_vault(self) -> None:
        """Changing a password should preserve data while invalidating the old password."""

        self._create_vault()
        new_password = "password456"

        v.change_password(
            self.vault_name,
            self.password,
            new_password
        )

        with self.assertRaises(FileNotFoundError):
            v.open_vault(
                self.vault_name,
                self.password
            )

        manifest = v.open_vault(
            self.vault_name,
            new_password
        )
        self.assertEqual(manifest.vault_name, self.vault_name)

        verification = v.verify_vault(
            self.vault_name,
            new_password
        )
        self.assertEqual(verification.file_count, 2)

    def test_verify_detects_corrupted_encrypted_blob(self) -> None:
        """Changing encrypted file bytes should fail authenticated verification."""

        self._create_vault()
        manifest = v.open_vault(
            self.vault_name,
            self.password
        )
        vault_path, _, _, _ = v._find_vault(
            self.vault_name,
            self.password
        )

        blob_path = vault_path / "data" / manifest.files[0].storage_name
        blob = bytearray(blob_path.read_bytes())
        blob[-1] ^= 0x01
        blob_path.write_bytes(blob)

        with self.assertRaises(ValueError):
            v.verify_vault(
                self.vault_name,
                self.password
            )

    def test_export_contains_versioned_metadata_and_checksum(self) -> None:
        """Export should create a TAR, sidecar checksum and public metadata."""

        vault_path, archive_path = self._create_export()
        hash_path = archive_path.with_suffix(
            archive_path.suffix + ".sha256"
        )

        self.assertTrue(archive_path.is_file())
        self.assertTrue(hash_path.is_file())
        self.assertEqual(
            hash_path.read_text(encoding="utf-8").strip(),
            v._calculate_file_sha256(archive_path)
        )

        with tarfile.open(archive_path, "r:*") as tar:
            export_file = tar.extractfile("export.json")
            self.assertIsNotNone(export_file)
            metadata = json.loads(export_file.read().decode("utf-8"))

        manifest = v.open_vault(
            self.vault_name,
            self.password
        )

        self.assertEqual(
            metadata["format"],
            vault_config.VAULT_EXPORT_FORMAT
        )
        self.assertEqual(
            metadata["version"],
            vault_config.VAULT_EXPORT_VERSION
        )
        self.assertEqual(metadata["vault_id"], vault_path.name)
        self.assertEqual(
            metadata["vault_format_version"],
            manifest.format_version
        )
        self.assertNotIn("vault_name", metadata)

    def test_export_refuses_to_overwrite_existing_archive(self) -> None:
        """A second export to the same destination must not overwrite files."""

        self._create_export()

        with self.assertRaises(FileExistsError):
            v.export_vault(
                self.vault_name,
                self.password,
                str(self.exports)
            )

    def test_import_round_trip(self) -> None:
        """Exported data should survive delete, import, unlock and full verification."""

        original_path, archive_path = self._create_export()
        original_vault_id = original_path.name
        shutil.rmtree(original_path)

        imported_path = v.import_vault(
            str(archive_path),
            self.password
        )

        self.assertEqual(imported_path.name, original_vault_id)
        self.assertTrue((imported_path / "key.enc").is_file())
        self.assertTrue((imported_path / "manifest.enc").is_file())
        self.assertTrue((imported_path / "data").is_dir())

        manifest = v.open_vault(
            self.vault_name,
            self.password
        )
        self.assertEqual(manifest.vault_id, original_vault_id)

        verification = v.verify_vault(
            self.vault_name,
            self.password
        )
        self.assertEqual(verification.file_count, 2)

    def test_import_rejects_wrong_password(self) -> None:
        """A valid archive must not import when key.enc cannot be unlocked."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                "wrong-password"
            )

        self.assertFalse(any(v.VAULT_ROOT.iterdir()))

    def test_import_rejects_missing_checksum(self) -> None:
        """Import requires the checksum sidecar shipped with the export."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)
        archive_path.with_suffix(
            archive_path.suffix + ".sha256"
        ).unlink()

        with self.assertRaises(FileNotFoundError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_corrupted_checksum(self) -> None:
        """Archive corruption should be detected before the TAR is trusted."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)
        hash_path = archive_path.with_suffix(
            archive_path.suffix + ".sha256"
        )
        hash_path.write_text("0" * 64, encoding="utf-8")

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_missing_export_metadata(self) -> None:
        """An archive without export.json must not reach extraction."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)

        entries = [
            (member, data)
            for member, data in self._read_archive_entries(archive_path)
            if member.name != "export.json"
        ]
        self._write_archive_entries(archive_path, entries)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_malformed_export_metadata(self) -> None:
        """Malformed JSON metadata should fail before archive extraction."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)
        entries = self._read_archive_entries(archive_path)

        for index, (member, data) in enumerate(entries):
            if member.name == "export.json":
                entries[index] = (member, b"{not-json")
                break

        self._write_archive_entries(archive_path, entries)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_wrong_export_format(self) -> None:
        """Archives using an unknown format identifier must fail closed."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)

        self._replace_export_metadata(
            archive_path,
            lambda metadata: {
                **metadata,
                "format": "not-a-vault-export",
            }
        )

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_invalid_vault_id(self) -> None:
        """The public vault identifier must be a non-empty hexadecimal value."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)

        self._replace_export_metadata(
            archive_path,
            lambda metadata: {
                **metadata,
                "vault_id": "not-hex",
            }
        )

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_duplicate_tar_entries(self) -> None:
        """Duplicate member names are ambiguous and must be rejected."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)
        entries = self._read_archive_entries(archive_path)

        export_member, export_data = next(
            (copy.copy(member), data)
            for member, data in entries
            if member.name == "export.json"
        )
        entries.append((export_member, export_data))
        self._write_archive_entries(archive_path, entries)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_unexpected_top_level_entry(self) -> None:
        """Only export.json and the declared vault directory may exist at TAR root."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)
        entries = self._read_archive_entries(archive_path)

        unexpected = tarfile.TarInfo("unexpected.txt")
        payload = b"unexpected"
        unexpected.size = len(payload)
        entries.append((unexpected, payload))
        self._write_archive_entries(archive_path, entries)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_unsupported_export_version(self) -> None:
        """Unknown outer export versions must fail closed."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)

        self._replace_export_metadata(
            archive_path,
            lambda metadata: {
                **metadata,
                "version": vault_config.VAULT_EXPORT_VERSION + 1,
            }
        )

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_unsupported_vault_format_version(self) -> None:
        """Unknown encrypted vault versions must fail before extraction."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)

        self._replace_export_metadata(
            archive_path,
            lambda metadata: {
                **metadata,
                "vault_format_version": vault_config.VAULT_FORMAT_VERSION + 1,
            }
        )

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_path_traversal(self) -> None:
        """TAR members may never escape the temporary extraction directory."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)
        entries = self._read_archive_entries(archive_path)

        malicious = tarfile.TarInfo("../outside.txt")
        payload = b"should never be extracted"
        malicious.size = len(payload)
        entries.append((malicious, payload))
        self._write_archive_entries(archive_path, entries)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

        self.assertFalse((self.root / "outside.txt").exists())

    def test_import_rejects_symlink_entries(self) -> None:
        """Links and other special TAR member types are not accepted."""

        vault_path, archive_path = self._create_export()
        vault_id = vault_path.name
        shutil.rmtree(vault_path)
        entries = self._read_archive_entries(archive_path)

        symlink = tarfile.TarInfo(
            f"{vault_id}/data/link.enc"
        )
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../../outside"
        entries.append((symlink, None))
        self._write_archive_entries(archive_path, entries)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_rejects_tampered_encrypted_blob(self) -> None:
        """Recomputed outer checksum cannot bypass inner AES-GCM verification."""

        vault_path, archive_path = self._create_export()
        shutil.rmtree(vault_path)
        entries = self._read_archive_entries(archive_path)

        for index, (member, data) in enumerate(entries):
            if (
                member.isfile()
                and "/data/" in member.name
                and data
            ):
                corrupted = bytearray(data)
                corrupted[-1] ^= 0x01
                entries[index] = (member, bytes(corrupted))
                break
        else:
            self.fail("No encrypted data blob found in export archive.")

        self._write_archive_entries(archive_path, entries)

        with self.assertRaises(ValueError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_import_refuses_existing_vault_id(self) -> None:
        """Import must never overwrite an already stored vault directory."""

        _, archive_path = self._create_export()

        with self.assertRaises(FileExistsError):
            v.import_vault(
                str(archive_path),
                self.password
            )

    def test_cli_export_import_round_trip(self) -> None:
        """CLI export/import commands should delegate to the working vault API."""

        vault_path = self._create_vault()
        archive_path = self.exports / f"{vault_path.name}.tar"
        runner = CliRunner()

        # Click 8.5 on Windows may route captured console output outside
        # CliRunner.result.output. Patch click.echo directly so this test checks
        # our CLI messages without depending on Click's stream implementation.
        with patch("src.cli.click.echo") as export_echo:
            export_result = runner.invoke(
                cli.vault,
                [
                    "export",
                    "--name", self.vault_name,
                    "--password", self.password,
                    "--destination", str(self.exports),
                ]
            )

        self.assertEqual(export_result.exit_code, 0)
        self.assertIsNone(export_result.exception)
        self.assertTrue(archive_path.is_file())
        self.assertTrue(archive_path.with_suffix(".tar.sha256").is_file())

        export_messages = [
            str(call.args[0])
            for call in export_echo.call_args_list
            if call.args
        ]
        self.assertTrue(
            any(message.startswith("Vault exported to:") for message in export_messages)
        )
        self.assertTrue(
            any(message.startswith("Checksum saved to:") for message in export_messages)
        )

        shutil.rmtree(vault_path)

        with patch("src.cli.click.echo") as import_echo:
            import_result = runner.invoke(
                cli.vault,
                [
                    "import",
                    "--archive", str(archive_path),
                    "--password", self.password,
                ]
            )

        self.assertEqual(import_result.exit_code, 0)
        self.assertIsNone(import_result.exception)
        self.assertTrue((v.VAULT_ROOT / vault_path.name).is_dir())

        import_messages = [
            str(call.args[0])
            for call in import_echo.call_args_list
            if call.args
        ]
        self.assertTrue(
            any(message.startswith("Vault imported to:") for message in import_messages)
        )

    def test_cli_exposes_export_and_import_commands(self) -> None:
        """The public CLI group should register both transfer operations."""

        # Inspect Click's command registry directly. This is more portable than
        # asserting help text captured by CliRunner on every terminal backend.
        self.assertIn("export", cli.vault.commands)
        self.assertIn("import", cli.vault.commands)

        export_command = cli.vault.commands["export"]
        import_command = cli.vault.commands["import"]

        export_parameters = {parameter.name for parameter in export_command.params}
        import_parameters = {parameter.name for parameter in import_command.params}

        self.assertEqual(
            export_parameters,
            {"name", "password", "destination"}
        )
        self.assertEqual(
            import_parameters,
            {"archive", "password"}
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
