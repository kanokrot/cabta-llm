"""Bootstrap the first admin user from email and password arguments."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.web.auth import hash_password


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {Path(sys.argv[0]).name} EMAIL PASSWORD", file=sys.stderr)
        return 2

    email = sys.argv[1].strip().lower()
    password = sys.argv[2]
    username = email.split("@", 1)[0]
    db_path = Path(os.getenv("AUTH_DB_PATH", "src/db/auth.db"))

    with sqlite3.connect(str(db_path)) as connection:
        existing = connection.execute(
            "SELECT id FROM users WHERE lower(email) = lower(?)", (email,)
        ).fetchone()
        duplicate = connection.execute(
            "SELECT id FROM users WHERE lower(username) = lower(?)", (username,)
        ).fetchone()
        if duplicate is not None and (
            existing is None or duplicate[0] != existing[0]
        ):
            raise SystemExit(f"Username already exists: {username}")

        password_hash = hash_password(password)
        if existing is None:
            connection.execute(
                "INSERT INTO users "
                "(email, username, password_hash, role, is_active) "
                "VALUES (?, ?, ?, 'admin', 1)",
                (email, username, password_hash),
            )
        else:
            connection.execute(
                "UPDATE users SET username = ?, password_hash = ?, "
                "role = 'admin', is_active = 1 WHERE id = ?",
                (username, password_hash, existing[0]),
            )
        connection.commit()

    print(
        f"Bootstrapped admin: email={email} "
        f"username={username} password={password}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
