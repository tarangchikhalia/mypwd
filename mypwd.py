#!/usr/bin/env python3
"""
Terminal-based password manager using Fernet authenticated encryption
"""

import os
import sys
import json
import getpass
import argparse
import base64
import stat
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Storage location
STORAGE_DIR = Path.home() / ".mypwd"
STORAGE_FILE = STORAGE_DIR / "passwords.enc"
SALT_FILE = STORAGE_DIR / "salt"
STORAGE_DIR_MODE = 0o700
STORAGE_FILE_MODE = 0o600
LEGACY_PBKDF2_ITERATIONS = 100000
DEFAULT_SCRYPT_N = 2**15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1


def ensure_storage_dir_secure():
    """Create storage directory if needed and enforce restrictive permissions."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STORAGE_DIR, STORAGE_DIR_MODE)
    current_mode = stat.S_IMODE(STORAGE_DIR.stat().st_mode)
    if current_mode != STORAGE_DIR_MODE:
        print(
            f"Error: Insecure permissions on '{STORAGE_DIR}'. Expected 0700.",
            file=sys.stderr,
        )
        sys.exit(1)


def enforce_file_mode(path, expected_mode):
    """Enforce strict file permissions and fail closed if they cannot be applied."""
    os.chmod(path, expected_mode)
    current_mode = stat.S_IMODE(path.stat().st_mode)
    if current_mode != expected_mode:
        print(
            f"Error: Insecure permissions on '{path}'. Expected {expected_mode:o}.",
            file=sys.stderr,
        )
        sys.exit(1)


def get_scrypt_parameter(env_name, default_value):
    """Read and validate a positive integer KDF parameter from environment."""
    value = os.environ.get(env_name, str(default_value))
    try:
        parsed = int(value)
    except ValueError:
        print(f"Error: {env_name} must be an integer.", file=sys.stderr)
        sys.exit(1)
    if parsed <= 0:
        print(f"Error: {env_name} must be greater than zero.", file=sys.stderr)
        sys.exit(1)
    return parsed


def get_scrypt_config():
    """Build scrypt settings for new key derivation metadata."""
    n = get_scrypt_parameter("MYPWD_SCRYPT_N", DEFAULT_SCRYPT_N)
    r = get_scrypt_parameter("MYPWD_SCRYPT_R", DEFAULT_SCRYPT_R)
    p = get_scrypt_parameter("MYPWD_SCRYPT_P", DEFAULT_SCRYPT_P)
    if n & (n - 1):
        print("Error: MYPWD_SCRYPT_N must be a power of two.", file=sys.stderr)
        sys.exit(1)
    return {
        "version": 2,
        "kdf": "scrypt",
        "salt": os.urandom(16),
        "n": n,
        "r": r,
        "p": p,
    }


def load_or_create_kdf_config():
    """Load existing KDF config or create new scrypt metadata for first use."""
    if not SALT_FILE.exists():
        return get_scrypt_config(), False

    enforce_file_mode(SALT_FILE, STORAGE_FILE_MODE)
    with open(SALT_FILE, "rb") as f:
        salt_data = f.read()

    try:
        config = json.loads(salt_data.decode())
    except Exception:
        config = None

    if isinstance(config, dict) and config.get("kdf") == "scrypt":
        try:
            return {
                "version": int(config["version"]),
                "kdf": "scrypt",
                "salt": base64.urlsafe_b64decode(config["salt"].encode()),
                "n": int(config["n"]),
                "r": int(config["r"]),
                "p": int(config["p"]),
            }, True
        except Exception:
            print("Error: Invalid KDF metadata in salt file.", file=sys.stderr)
            sys.exit(1)

    # Backward compatibility for legacy raw-salt PBKDF2 files.
    return {
        "version": 1,
        "kdf": "pbkdf2",
        "salt": salt_data,
        "iterations": LEGACY_PBKDF2_ITERATIONS,
    }, True


def persist_kdf_config(kdf_config):
    """Persist KDF metadata in the salt file."""
    serializable = {
        "version": kdf_config["version"],
        "kdf": kdf_config["kdf"],
        "salt": base64.urlsafe_b64encode(kdf_config["salt"]).decode(),
        "n": kdf_config["n"],
        "r": kdf_config["r"],
        "p": kdf_config["p"],
    }
    with os.fdopen(
        os.open(SALT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, STORAGE_FILE_MODE),
        "wb",
    ) as f:
        f.write(json.dumps(serializable).encode())
    enforce_file_mode(SALT_FILE, STORAGE_FILE_MODE)


def derive_key(master_password, kdf_config):
    """Derive an encryption key from the master password."""
    if kdf_config["kdf"] == "scrypt":
        kdf = Scrypt(
            salt=kdf_config["salt"],
            length=32,
            n=kdf_config["n"],
            r=kdf_config["r"],
            p=kdf_config["p"],
        )
    else:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=kdf_config["salt"],
            iterations=kdf_config["iterations"],
        )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def get_master_key():
    """Prompt for master password and derive encryption key"""
    master_password = getpass.getpass("Master password: ")
    ensure_storage_dir_secure()

    kdf_config, exists = load_or_create_kdf_config()
    if not exists:
        persist_kdf_config(kdf_config)

    key = derive_key(master_password, kdf_config)
    return Fernet(key)


def load_passwords(cipher):
    """Load and decrypt password storage"""
    if not STORAGE_FILE.exists():
        return {}

    enforce_file_mode(STORAGE_FILE, STORAGE_FILE_MODE)
    try:
        with open(STORAGE_FILE, "rb") as f:
            encrypted_data = f.read()

        if not encrypted_data:
            return {}

        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    except Exception as e:
        print(
            f"Error: Failed to decrypt. Wrong master password or corrupted file.\n Error: {e}",
            file=sys.stderr,
        )
        sys.exit(1)


def save_passwords(cipher, passwords):
    """Encrypt and save password storage"""
    ensure_storage_dir_secure()

    json_data = json.dumps(passwords).encode()
    encrypted_data = cipher.encrypt(json_data)

    with os.fdopen(
        os.open(STORAGE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, STORAGE_FILE_MODE),
        "wb",
    ) as f:
        f.write(encrypted_data)
    enforce_file_mode(STORAGE_FILE, STORAGE_FILE_MODE)


def add_password(tag, username, password):
    """Add or update a password"""
    cipher = get_master_key()
    passwords = load_passwords(cipher)

    username_password = ":".join([username, password])
    passwords[tag] = username_password
    save_passwords(cipher, passwords)

    print(f"Password for '{tag}' saved successfully.")


def read_password(password_stdin=False):
    """Read a password from stdin or an interactive prompt."""
    if password_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            print("Error: No password provided on stdin.", file=sys.stderr)
            sys.exit(1)
        return password

    password = getpass.getpass("Entry password: ")
    if not password:
        print("Error: Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    return password


def get_password(tag, output=False, clipboard=False):
    """Retrieve a password"""
    cipher = get_master_key()
    passwords = load_passwords(cipher)

    if tag not in passwords:
        print(f"Error: No password found for tag '{tag}'", file=sys.stderr)
        sys.exit(1)

    username_password = passwords[tag]

    username, password = username_password.split(
        ":", 1
    )  # split the username password pair with first occurance of ":"

    if output:
        print(f"Username: {username}")
        print(f"Password: {password}")
    elif clipboard:
        # Copy to clipboard
        try:
            import pyperclip

            pyperclip.copy(password)
            print(f"Username for '{tag}' is '{username}'")
            print(f"Password for '{tag}' copied to clipboard.")
        except ImportError:
            print(
                "Error: pyperclip not installed. Install with: pip install pyperclip",
                file=sys.stderr,
            )
            print(f"Password: {password}")
    else:
        print(f"Username: {username}")
        print("Password not copied. Use --output or --clipboard.")


def list_tags():
    """List all stored tags"""
    cipher = get_master_key()
    passwords = load_passwords(cipher)

    if not passwords:
        print("No passwords stored.")
        return

    print("Stored tags:")
    for tag in sorted(passwords.keys()):
        print(f"  - {tag}")


def main():
    parser = argparse.ArgumentParser(description="Terminal-based password manager")
    parser.add_argument(
        "--add",
        metavar="<tag>",
        help="Add or update a password",
    )
    parser.add_argument(
        "--username",
        metavar="<username>",
        help="Username for the password entry (use with --add)",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read entry password from stdin instead of prompt (use with --add)",
    )
    parser.add_argument(
        "--get", metavar="<tag>", help="Get credentials for a tag"
    )
    parser.add_argument(
        "--output",
        action="store_true",
        help="Output password to terminal (use with --get)",
    )
    parser.add_argument(
        "--clipboard",
        action="store_true",
        help="Copy password to clipboard (use with --get)",
    )
    parser.add_argument("--list", action="store_true", help="List all stored tags")

    args = parser.parse_args()

    if args.password_stdin and not args.add:
        parser.error("--password-stdin can only be used with --add")
    if args.output and args.clipboard:
        parser.error("--output and --clipboard cannot be used together")

    if args.add:
        if not args.username:
            parser.error("--username is required when using --add")
        tag = args.add
        username = args.username
        password = read_password(password_stdin=args.password_stdin)
        add_password(tag, username, password)

    elif args.get:
        get_password(args.get, output=args.output, clipboard=args.clipboard)

    elif args.list:
        list_tags()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
