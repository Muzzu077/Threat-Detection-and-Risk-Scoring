"""
TrustFlow — first-admin bootstrap CLI.

Creates an admin user without committing credentials to the repo. Intended to be
run once after the stack comes up for the first time.

Usage:
    docker compose exec api python -m src.bootstrap_admin --email you@example.com
    # ...prompts for password (won't be echoed)

Or non-interactively:
    docker compose exec api python -m src.bootstrap_admin \\
        --email you@example.com --password 'hunter2' --display-name "Ops Lead"

Idempotent: if a user with the given email already exists, prints a notice and
exits 0 without modifying anything. Use --force to promote an existing user to
admin role.
"""
import argparse
import getpass
import sys

from src.database import db
from src.auth import hash_password


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap the first TrustFlow admin user.")
    parser.add_argument("--email", required=True, help="Admin email address.")
    parser.add_argument("--password", default=None, help="Password (omit for interactive prompt).")
    parser.add_argument("--display-name", default="Administrator", help="Display name.")
    parser.add_argument("--force", action="store_true", help="Promote an existing user to admin.")
    args = parser.parse_args()

    email = args.email.strip().lower()
    if not email or "@" not in email:
        print("error: --email must be a valid address", file=sys.stderr)
        return 2

    existing = db.get_user_by_email(email)
    if existing and not args.force:
        print(f"User {email} already exists (id={existing.id}, role={existing.role}). "
              f"Use --force to promote to admin.")
        return 0

    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm: ")
        if password != confirm:
            print("error: passwords do not match", file=sys.stderr)
            return 2
    if len(password) < 8:
        print("error: password must be at least 8 characters", file=sys.stderr)
        return 2

    if existing and args.force:
        session = db.Session()
        try:
            from src.database import User
            user = session.query(User).filter(User.id == existing.id).first()
            user.role = "admin"
            user.password_hash = hash_password(password)
            user.display_name = args.display_name
            session.commit()
            print(f"Promoted {email} to admin (id={user.id}).")
            return 0
        finally:
            session.close()

    user = db.create_user(
        email=email,
        password_hash=hash_password(password),
        display_name=args.display_name,
        role="admin",
    )
    print(f"Created admin user {email} (id={user.id}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
