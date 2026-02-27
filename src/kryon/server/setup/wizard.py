"""First-run setup wizard — CLI and web versions."""

from __future__ import annotations

import getpass
import logging
from pathlib import Path

from kryon.server.setup.env_writer import generate_jwt_secret, write_env_file

logger = logging.getLogger(__name__)


def needs_setup(db_path: Path | None = None) -> bool:
    """Check if setup is needed (no admin users exist)."""
    try:
        from kryon.memory.store import MemoryStore
        store = MemoryStore(db_path=db_path)
        users = store.list_users()
        store.close()
        return len(users) == 0
    except Exception:
        return True


def run_cli_wizard(db_path: Path | None = None) -> dict:
    """Run the interactive CLI setup wizard.

    Returns a dict with the configuration created.
    """
    print("\n" + "=" * 50)
    print("  KRYON — First-Run Setup Wizard")
    print("=" * 50 + "\n")

    # 1. Create admin user
    print("[1/3] Create administrator account\n")
    username = input("  Admin username [admin]: ").strip() or "admin"
    email = input("  Admin email [admin@localhost]: ").strip() or "admin@localhost"

    while True:
        password = getpass.getpass("  Admin password: ")
        if len(password) < 8:
            print("  Password must be at least 8 characters.")
            continue
        confirm = getpass.getpass("  Confirm password: ")
        if password != confirm:
            print("  Passwords do not match.")
            continue
        break

    # 2. Generate JWT secret
    print("\n[2/3] Security configuration\n")
    jwt_secret = generate_jwt_secret()
    print("  JWT secret generated (stored in .env)")

    # 3. CORS configuration
    print("\n[3/3] Network configuration\n")
    default_origins = "http://localhost:5173,http://localhost:8700"
    cors_input = input(f"  CORS origins [{default_origins}]: ").strip()
    cors_origins = cors_input or default_origins

    # Write .env file
    env_path = write_env_file(jwt_secret=jwt_secret, cors_origins=cors_origins)
    print(f"\n  Configuration written to: {env_path}")

    # Create admin user in DB
    from kryon.memory.store import MemoryStore
    from kryon.server.auth.models import User
    from kryon.server.auth.password import hash_password

    store = MemoryStore(db_path=db_path)
    admin = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin",
    )
    store.create_user(admin)
    store.close()

    print(f"  Admin user '{username}' created.")
    print("\n" + "=" * 50)
    print("  Setup complete! Start the server with: kryon --serve")
    print("=" * 50 + "\n")

    return {
        "username": username,
        "email": email,
        "jwt_secret": jwt_secret,
        "cors_origins": cors_origins,
        "env_path": str(env_path),
    }
