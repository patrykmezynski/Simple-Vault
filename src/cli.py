import click

from src import vault as vault_api


@click.group()
def vault():
    """Main command group for the vault manager CLI."""
    pass


@vault.command(name="list")
@click.option(
    "--unlock",
    is_flag=True,
    help="Prompt for a password and decrypt matching vault names."
)
def list_vaults_command(unlock):
    """
    List available vaults.

    Vault names are encrypted and cannot be displayed without a valid
    password. By default only random vault identifiers are shown.
    """

    try:
        password = None

        if unlock:
            # Password is requested interactively so it does not appear
            # in shell history.
            password = click.prompt(
                "Password",
                hide_input=True
            )

        entries = vault_api.list_vaults(password)

        if not entries:
            click.echo("No vaults found.")
            return

        click.echo("")

        for entry in entries:
            if entry.unlocked:
                click.echo(
                    f"{entry.vault_id}  {entry.vault_name}"
                )
            else:
                click.echo(
                    f"{entry.vault_id}  <encrypted name>"
                )

    except Exception as e:
        click.echo(
            f"Error listing vaults: {e}"
        )


@vault.command()
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault to create."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=True,
    help="The password for the vault."
)
@click.option(
    "--source",
    prompt="Source folder",
    help="The source folder for the vault."
)
def create(name, password, source):
    """
    Create a new encrypted vault from a source folder.

    CLI options are passed to vault.create_vault(). This function only
    handles user input and displays the operation result.
    """

    try:
        # Pass CLI arguments to the vault API.
        success = vault_api.create_vault(
            name,
            password,
            source
        )

        # Display result returned by create_vault().
        if success:
            click.echo(
                f"Vault '{name}' created successfully."
            )
        else:
            click.echo(
                f"Failed to create vault '{name}'."
            )

    except Exception as e:
        click.echo(
            f"Error creating vault: {e}"
        )


@vault.command()
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault to open."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="The password for the vault."
)
def open(name, password):
    """
    Open a vault and display the list of files stored inside it.

    Only the authenticated encrypted manifest is opened here. File contents
    remain encrypted until the extract command is used.
    """

    try:
        # Open vault and receive its decrypted manifest.
        manifest = vault_api.open_vault(
            name,
            password
        )

        click.echo(
            f"\nVault: {manifest.vault_name}"
        )
        click.echo("")

        # Display original file paths and human-readable sizes.
        for file in manifest.files:
            click.echo(
                f"{_format_size(file.size):>12}  {file.path}"
            )

    except Exception as e:
        click.echo(
            f"Error opening vault: {e}"
        )


@vault.command()
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="The password for the vault."
)
@click.option(
    "--source",
    prompt="Source file",
    help="The plaintext file to add to the vault."
)
@click.option(
    "--path",
    "file_path",
    default=None,
    help="Optional path used inside the vault."
)
def add(name, password, source, file_path):
    """
    Add one file without rebuilding the complete vault.

    Only the new file is encrypted. The existing encrypted data files remain
    untouched and the authenticated manifest is updated afterwards.
    """

    try:
        file_entry = vault_api.add_file(
            name,
            password,
            source,
            file_path
        )

        click.echo(
            f"File added as '{file_entry.path}'."
        )

    except Exception as e:
        click.echo(
            f"Error adding file: {e}"
        )


@vault.command()
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="The password for the vault."
)
@click.option(
    "--file",
    "file_path",
    prompt="File path",
    help="The path of the file inside the vault."
)
def remove(name, password, file_path):
    """
    Remove one selected file from a vault.

    Only the selected encrypted blob and its manifest entry are removed.
    Other encrypted files are not decrypted or rebuilt.
    """

    try:
        vault_api.remove_file(
            name,
            password,
            file_path
        )

        click.echo(
            f"File '{file_path}' removed successfully."
        )

    except Exception as e:
        click.echo(
            f"Error removing file: {e}"
        )


@vault.command()
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="The password for the vault."
)
@click.option(
    "--file",
    "file_path",
    prompt="Current file path",
    help="The current path of the file inside the vault."
)
@click.option(
    "--new-path",
    prompt="New file path",
    help="The new path or name inside the vault."
)
def rename(name, password, file_path, new_path):
    """
    Rename or move one file inside the vault.

    File contents remain encrypted and unchanged. Only authenticated metadata
    inside manifest.enc is updated.
    """

    try:
        file_entry = vault_api.rename_file(
            name,
            password,
            file_path,
            new_path
        )

        click.echo(
            f"File renamed to '{file_entry.path}'."
        )

    except Exception as e:
        click.echo(
            f"Error renaming file: {e}"
        )


@vault.command()
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="The password for the vault."
)
@click.option(
    "--file",
    "file_path",
    prompt="File path",
    help="The path of the file inside the vault."
)
@click.option(
    "--destination",
    prompt="Destination folder",
    default="output",
    show_default=True,
    help="The folder where the file will be extracted."
)
def extract(name, password, file_path, destination):
    """
    Extract one selected file from a vault.

    The requested file is decrypted and verified independently. Corrupted
    plaintext is never published to the selected destination.
    """

    try:
        # Extract only the file selected by the user.
        output_path = vault_api.extract_file(
            name,
            password,
            file_path,
            destination
        )

        click.echo(
            f"File extracted to '{output_path}'."
        )

    except Exception as e:
        click.echo(
            f"Error extracting file: {e}"
        )



@vault.command(name="change-password")
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault."
)
@click.option(
    "--password",
    "current_password",
    prompt="Current password",
    hide_input=True,
    confirmation_prompt=False,
    help="The current vault password."
)
@click.option(
    "--new-password",
    prompt="New password",
    hide_input=True,
    confirmation_prompt=True,
    help="The new password used to protect the vault."
)
def change_password_command(name, current_password, new_password):
    """
    Change the vault password without re-encrypting stored files.

    Only the encrypted master key inside key.enc is re-wrapped. Encrypted
    manifest and data files remain unchanged.
    """

    try:
        vault_api.change_password(
            name,
            current_password,
            new_password
        )

        click.echo(
            f"Password for vault '{name}' changed successfully."
        )

    except Exception as e:
        click.echo(
            f"Error changing vault password: {e}"
        )


@vault.command()
@click.option(
    "--name",
    prompt="Vault name",
    help="The name of the vault to verify."
)
@click.option(
    "--password",
    prompt=True,
    hide_input=True,
    confirmation_prompt=False,
    help="The password for the vault."
)
def verify(name, password):
    """
    Verify the complete vault without extracting plaintext files.

    The command authenticates key.enc and manifest.enc, then verifies every
    encrypted file chunk, file identity, size and SHA-256 in memory.
    """

    try:
        result = vault_api.verify_vault(
            name,
            password
        )

        click.echo(
            f"Vault '{result.vault_name}' verified successfully."
        )
        click.echo(
            f"Files: {result.file_count}"
        )
        click.echo(
            f"Directories: {result.directory_count}"
        )
        click.echo(
            f"Total size: {_format_size(result.total_size)}"
        )

    except Exception as e:
        click.echo(
            f"Vault verification failed: {e}"
        )

def _format_size(size: int) -> str:
    """
    Convert file size in bytes to a human-readable value.

    Args:
        size (int): File size in bytes.

    Returns:
        str: Formatted size using B, KB, MB or GB.
    """

    if size >= 1024 * 1024 * 1024:
        return f"{size / 1024 / 1024 / 1024:.2f} GB"

    if size >= 1024 * 1024:
        return f"{size / 1024 / 1024:.2f} MB"

    if size >= 1024:
        return f"{size / 1024:.2f} KB"

    return f"{size} B"
