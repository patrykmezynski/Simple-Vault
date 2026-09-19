
def create_vault(vault_name: str, password: str) -> bool:
    """
    Create a new vault with the given name and password.

    Args:
        vault_name (str): The name of the vault to create.
        password (str): The password for the vault.

    Returns:
        bool: True if the vault was created successfully, False otherwise.
    """
    try:
        create_vault(vault_name, password)
        return True
    except Exception as e:
        print(f"Error creating vault: {e}")
        return False