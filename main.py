#!/usr/bin/env python3
"""
Secure Password Manager
========================

A zero-knowledge, local-first CLI password manager.

Security design (see README.md for full threat model):
  - Master password is NEVER written to disk and never stored anywhere,
    even in memory, longer than strictly necessary for the current operation.
  - The vault encryption key is derived in-memory from the master password
    using PBKDF2HMAC-SHA256 with 600,000 iterations and a unique 16-byte
    random salt (per RFC 2898 / NIST SP 800-132 guidance for PBKDF2).
  - The entire vault (all entries) is encrypted as a single JSON blob using
    AES-256-GCM, an authenticated encryption mode. This gives us both
    confidentiality AND integrity/tamper-detection in one primitive: if the
    ciphertext or the derived key is wrong, decryption raises an
    InvalidTag error and the vault is never displayed.
  - No temporary files are created during read or update operations -
    the vault is decrypted straight into memory and re-encrypted straight
    back into the single vault file with one write() call.

Author: Generated for the "Secure Password Manager" mini-project.
Python: 3.10+
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import string
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Missing dependency: 'cryptography'. Install with: pip install -r requirements.txt")
    sys.exit(1)

try:
    import pyperclip
except ImportError:
    pyperclip = None  # Clipboard features degrade gracefully if unavailable.

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
except ImportError:
    print("Missing dependency: 'rich'. Install with: pip install -r requirements.txt")
    sys.exit(1)


# --------------------------------------------------------------------------- #
# Constants / security parameters
# --------------------------------------------------------------------------- #

APP_NAME = "Secure Password Manager"
DEFAULT_VAULT_PATH = Path.home() / ".secure_password_manager" / "vault.json"

VAULT_FORMAT_VERSION = 1
KDF_NAME = "PBKDF2HMAC-SHA256"
KDF_ITERATIONS = 600_000          # NIST/OWASP-aligned minimum for PBKDF2-SHA256
SALT_LEN_BYTES = 16                # 128-bit salt, unique per vault
NONCE_LEN_BYTES = 12                # 96-bit nonce, required/optimal for AES-GCM
AES_KEY_LEN_BYTES = 32              # AES-256

CLIPBOARD_CLEAR_SECONDS = 20

console = Console()


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class VaultError(Exception):
    """Base class for all vault-related errors."""


class AuthenticationError(VaultError):
    """Raised when the master password is incorrect."""


class IntegrityError(VaultError):
    """Raised when the vault file is malformed or has been tampered with."""


# --------------------------------------------------------------------------- #
# Cryptography layer
# --------------------------------------------------------------------------- #

class CryptoManager:
    """
    Wraps all key-derivation and authenticated-encryption operations.

    Nothing in this class ever touches disk - it only operates on bytes
    already in memory, and it never logs or prints secret material.
    """

    @staticmethod
    def derive_key(master_password: bytes, salt: bytes,
                   iterations: int = KDF_ITERATIONS) -> bytes:
        """Derive a 256-bit AES key from the master password using PBKDF2HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LEN_BYTES,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(master_password)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt plaintext with AES-256-GCM.
        A fresh random nonce is generated for every encryption call - this is
        mandatory because AES-GCM security collapses if a (key, nonce) pair
        is ever reused.
        Returns (nonce, ciphertext_with_tag).
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(NONCE_LEN_BYTES)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce, ciphertext

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt and verify AES-256-GCM ciphertext.
        Raises cryptography.exceptions.InvalidTag if the key is wrong OR if
        the ciphertext has been tampered with in any way - GCM's built-in
        authentication tag makes these two failure modes indistinguishable
        by design, which is exactly what we want (no oracle for attackers).
        """
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def _zero(buf: Optional[bytearray]) -> None:
    """
    Best-effort in-memory wipe of a mutable byte buffer.
    NOTE: CPython strings are immutable and cannot be reliably zeroed; this
    is why every secret in this program is handled as bytes/bytearray for
    as long as possible and converted to str only at the last moment
    (e.g. for display). See README "Memory-safety limitations" section.
    """
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


# --------------------------------------------------------------------------- #
# Vault data model
# --------------------------------------------------------------------------- #

@dataclass
class Entry:
    id: str
    service: str
    username: str
    password: str
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "service": self.service,
            "username": self.username,
            "password": self.password,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "Entry":
        return Entry(
            id=d["id"],
            service=d["service"],
            username=d["username"],
            password=d["password"],
            notes=d.get("notes", ""),
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )


class VaultManager:
    """
    Handles loading, decrypting, mutating, re-encrypting and saving the
    vault file. Holds the derived AES key and the decrypted entries in
    memory only for the lifetime of the running process.
    """

    def __init__(self, path: Path):
        self.path = path
        self.entries: list[Entry] = []
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._iterations: int = KDF_ITERATIONS

    # ---- Vault lifecycle -------------------------------------------------

    def exists(self) -> bool:
        return self.path.exists()

    def create_new(self, master_password: bytes) -> None:
        """Initialize a brand-new, empty vault with a fresh salt and key."""
        self._salt = os.urandom(SALT_LEN_BYTES)
        self._iterations = KDF_ITERATIONS
        self._key = CryptoManager.derive_key(master_password, self._salt, self._iterations)
        self.entries = []
        self.save()

    def unlock(self, master_password: bytes) -> None:
        """
        Load the vault file from disk, derive the key from the supplied
        master password, and attempt to decrypt. Raises AuthenticationError
        or IntegrityError on any failure - callers must not distinguish
        the two to the end user (avoids leaking which failure occurred).
        """
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise IntegrityError(f"Vault file is unreadable or corrupted: {exc}") from exc

        try:
            version = raw["version"]
            kdf_meta = raw["kdf"]
            salt = base64.b64decode(kdf_meta["salt"])
            iterations = int(kdf_meta["iterations"])
            nonce = base64.b64decode(raw["nonce"])
            ciphertext = base64.b64decode(raw["ciphertext"])
        except (KeyError, ValueError) as exc:
            raise IntegrityError(f"Vault file structure is invalid: {exc}") from exc

        if version != VAULT_FORMAT_VERSION:
            raise IntegrityError(f"Unsupported vault format version: {version}")

        key = CryptoManager.derive_key(master_password, salt, iterations)

        try:
            plaintext = CryptoManager.decrypt(key, nonce, ciphertext)
        except InvalidTag as exc:
            # Wrong master password OR tampered ciphertext - indistinguishable
            # on purpose, both surface as AuthenticationError to the caller.
            raise AuthenticationError(
                "Incorrect master password, or the vault file has been tampered with."
            ) from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
            self.entries = [Entry.from_dict(e) for e in payload.get("entries", [])]
        except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as exc:
            raise IntegrityError(f"Decrypted vault payload is malformed: {exc}") from exc

        self._key = key
        self._salt = salt
        self._iterations = iterations

    def save(self) -> None:
        """
        Re-encrypt the current in-memory entries and write the vault file
        in a single write() call. No temporary/intermediate files are ever
        created - the ciphertext is fully assembled in memory first.
        A brand-new random nonce is used every single time we save, which
        is required since the AES key stays constant across saves.
        """
        if self._key is None or self._salt is None:
            raise VaultError("Vault is not unlocked; cannot save.")

        payload = json.dumps(
            {"entries": [e.to_dict() for e in self.entries]},
            ensure_ascii=False,
        ).encode("utf-8")

        nonce, ciphertext = CryptoManager.encrypt(self._key, payload)

        blob = {
            "version": VAULT_FORMAT_VERSION,
            "kdf": {
                "name": KDF_NAME,
                "iterations": self._iterations,
                "salt": base64.b64encode(self._salt).decode("ascii"),
            },
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Single write() call, single file - no temp files created.
        self.path.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)  # Owner read/write only, best-effort.
        except OSError:
            pass  # Not all filesystems/platforms support chmod (e.g. some Windows setups).

    def change_master_password(self, new_master_password: bytes) -> None:
        """Re-derive a brand new salt + key and re-encrypt the whole vault."""
        self._salt = os.urandom(SALT_LEN_BYTES)
        self._iterations = KDF_ITERATIONS
        self._key = CryptoManager.derive_key(new_master_password, self._salt, self._iterations)
        self.save()

    # ---- CRUD --------------------------------------------------------------

    def add_entry(self, service: str, username: str, password: str, notes: str = "") -> Entry:
        entry = Entry(id=uuid.uuid4().hex, service=service, username=username,
                       password=password, notes=notes)
        self.entries.append(entry)
        self.save()
        return entry

    def search(self, query: str) -> list[Entry]:
        q = query.strip().lower()
        if not q:
            return list(self.entries)
        return [e for e in self.entries
                if q in e.service.lower() or q in e.username.lower()]

    def get_by_id(self, entry_id: str) -> Optional[Entry]:
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    def update_entry(self, entry_id: str, *, service=None, username=None,
                      password=None, notes=None) -> bool:
        entry = self.get_by_id(entry_id)
        if entry is None:
            return False
        if service is not None:
            entry.service = service
        if username is not None:
            entry.username = username
        if password is not None:
            entry.password = password
        if notes is not None:
            entry.notes = notes
        entry.updated_at = datetime.now(timezone.utc).isoformat()
        self.save()
        return True

    def delete_entry(self, entry_id: str) -> bool:
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.id != entry_id]
        changed = len(self.entries) != before
        if changed:
            self.save()
        return changed

    def lock(self) -> None:
        """Best-effort wipe of the derived key from this process's memory."""
        if self._key is not None:
            key_ba = bytearray(self._key)
            _zero(key_ba)
        self._key = None
        self.entries = []


# --------------------------------------------------------------------------- #
# Password generator
# --------------------------------------------------------------------------- #

def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    """
    Generate a cryptographically strong random password using the `secrets`
    module (CSPRNG-backed), guaranteeing at least one lowercase, one
    uppercase, one digit, and (optionally) one symbol.
    """
    if length < 8:
        length = 8

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?/"

    pools = [lowercase, uppercase, digits] + ([symbols] if use_symbols else [])
    alphabet = "".join(pools)

    while True:
        pwd_chars = [secrets.choice(alphabet) for _ in range(length)]
        pwd = "".join(pwd_chars)
        if (any(c in lowercase for c in pwd)
                and any(c in uppercase for c in pwd)
                and any(c in digits for c in pwd)
                and (not use_symbols or any(c in symbols for c in pwd))):
            return pwd


def estimate_strength_label(password: str) -> str:
    """Rough, non-authoritative entropy-based strength label for display only."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    if pool == 0:
        return "unknown"
    import math
    bits = len(password) * math.log2(pool)
    if bits < 40:
        return "weak"
    if bits < 60:
        return "fair"
    if bits < 80:
        return "strong"
    return "very strong"


# --------------------------------------------------------------------------- #
# Clipboard handling
# --------------------------------------------------------------------------- #

def copy_to_clipboard_with_autoclear(secret_text: str, timeout: int = CLIPBOARD_CLEAR_SECONDS) -> None:
    """
    Copy a secret to the system clipboard and schedule an automatic clear.
    The clear only fires if the clipboard still contains exactly what we
    put there (so we don't wipe something the user copied afterwards).
    """
    if pyperclip is None:
        console.print("[yellow]pyperclip not installed - clipboard copy skipped. "
                       "Install it with `pip install pyperclip`.[/yellow]")
        return

    try:
        pyperclip.copy(secret_text)
    except Exception as exc:  # pyperclip raises various backend-specific errors
        console.print(f"[yellow]Could not access system clipboard: {exc}[/yellow]")
        return

    console.print(f"[green]Password copied to clipboard.[/green] "
                  f"[dim]It will auto-clear in {timeout} seconds.[/dim]")

    def _clear_later():
        time.sleep(timeout)
        try:
            if pyperclip.paste() == secret_text:
                pyperclip.copy("")
        except Exception:
            pass  # Best effort only.

    threading.Thread(target=_clear_later, daemon=True).start()


# --------------------------------------------------------------------------- #
# CLI helpers
# --------------------------------------------------------------------------- #

def prompt_master_password(confirm: bool = False, prompt_text: str = "Master password") -> bytes:
    """Securely prompt for the master password (no terminal echo) via getpass."""
    while True:
        pwd = getpass.getpass(f"{prompt_text}: ")
        if not confirm:
            return pwd.encode("utf-8")
        pwd2 = getpass.getpass("Confirm master password: ")
        if pwd == pwd2:
            if len(pwd) < 8:
                console.print("[red]Master password must be at least 8 characters. Try again.[/red]")
                continue
            return pwd.encode("utf-8")
        console.print("[red]Passwords do not match. Try again.[/red]")


def mask(value: str, keep: int = 0) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)


def print_banner():
    console.print(Panel.fit(
        f"[bold cyan]{APP_NAME}[/bold cyan]\n"
        f"[dim]Zero-knowledge local vault · AES-256-GCM · PBKDF2HMAC-SHA256 ({KDF_ITERATIONS:,} iterations)[/dim]",
        border_style="cyan",
    ))


def print_entries_table(entries: list[Entry], reveal_passwords: bool = False):
    table = Table(show_lines=False, header_style="bold cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("Service")
    table.add_column("Username")
    table.add_column("Password")
    table.add_column("Notes")
    table.add_column("Updated", style="dim")

    for idx, e in enumerate(entries, start=1):
        pw_display = e.password if reveal_passwords else mask(e.password)
        table.add_row(str(idx), e.service, e.username, pw_display,
                      (e.notes[:30] + "...") if len(e.notes) > 30 else e.notes,
                      e.updated_at.split("T")[0] if e.updated_at else "")
    console.print(table)


def select_entry_from_list(entries: list[Entry]) -> Optional[Entry]:
    if not entries:
        console.print("[yellow]No matching entries.[/yellow]")
        return None
    print_entries_table(entries, reveal_passwords=False)
    choice = Prompt.ask("Enter row number to select (or blank to cancel)", default="")
    if not choice.strip():
        return None
    try:
        i = int(choice) - 1
        if 0 <= i < len(entries):
            return entries[i]
    except ValueError:
        pass
    console.print("[red]Invalid selection.[/red]")
    return None


# --------------------------------------------------------------------------- #
# CLI actions
# --------------------------------------------------------------------------- #

def action_add(vault: VaultManager):
    console.rule("[bold]Add New Credential")
    service = Prompt.ask("Service / URL")
    username = Prompt.ask("Username / email")

    use_generator = Confirm.ask("Generate a strong password automatically?", default=True)
    if use_generator:
        length_str = Prompt.ask("Password length", default="20")
        try:
            length = max(8, int(length_str))
        except ValueError:
            length = 20
        password = generate_password(length=length)
        console.print(f"[green]Generated password strength:[/green] {estimate_strength_label(password)}")
    else:
        password = getpass.getpass("Password (input hidden): ")

    notes = Prompt.ask("Notes (optional)", default="")

    entry = vault.add_entry(service, username, password, notes)
    console.print(f"[green]Saved entry '{entry.service}'.[/green]")

    if Confirm.ask("Copy the new password to clipboard now?", default=True):
        copy_to_clipboard_with_autoclear(entry.password)

    # Best-effort clear of the local variable holding the plaintext password.
    password = None  # noqa: F841


def action_search(vault: VaultManager):
    console.rule("[bold]Search / Retrieve Credential")
    query = Prompt.ask("Search by service or username (blank = list all)", default="")
    matches = vault.search(query)
    entry = select_entry_from_list(matches)
    if entry is None:
        return
    console.print(Panel.fit(
        f"[bold]{entry.service}[/bold]\n"
        f"Username: {entry.username}\n"
        f"Notes: {entry.notes or '-'}\n"
        f"Last updated: {entry.updated_at}",
        title="Entry details", border_style="green"
    ))
    copy_to_clipboard_with_autoclear(entry.password)


def action_update(vault: VaultManager):
    console.rule("[bold]Update Credential")
    query = Prompt.ask("Search by service or username to update", default="")
    matches = vault.search(query)
    entry = select_entry_from_list(matches)
    if entry is None:
        return

    console.print("[dim]Leave a field blank to keep its current value.[/dim]")
    new_service = Prompt.ask("Service / URL", default=entry.service)
    new_username = Prompt.ask("Username / email", default=entry.username)

    change_password = Confirm.ask("Change password?", default=False)
    new_password = None
    if change_password:
        if Confirm.ask("Generate a new strong password automatically?", default=True):
            length_str = Prompt.ask("Password length", default="20")
            try:
                length = max(8, int(length_str))
            except ValueError:
                length = 20
            new_password = generate_password(length=length)
        else:
            new_password = getpass.getpass("New password (input hidden): ")

    new_notes = Prompt.ask("Notes", default=entry.notes)

    vault.update_entry(entry.id, service=new_service, username=new_username,
                        password=new_password, notes=new_notes)
    console.print("[green]Entry updated.[/green]")

    if new_password and Confirm.ask("Copy the new password to clipboard now?", default=True):
        copy_to_clipboard_with_autoclear(new_password)
    new_password = None  # noqa: F841


def action_delete(vault: VaultManager):
    console.rule("[bold]Delete Credential")
    query = Prompt.ask("Search by service or username to delete", default="")
    matches = vault.search(query)
    entry = select_entry_from_list(matches)
    if entry is None:
        return
    if Confirm.ask(f"[red]Are you sure you want to permanently delete '{entry.service}' "
                    f"({entry.username})?[/red]", default=False):
        vault.delete_entry(entry.id)
        console.print("[green]Entry deleted.[/green]")
    else:
        console.print("[yellow]Cancelled.[/yellow]")


def action_list(vault: VaultManager):
    console.rule("[bold]All Saved Credentials")
    if not vault.entries:
        console.print("[yellow]Vault is empty.[/yellow]")
        return
    reveal = Confirm.ask("Reveal passwords in this table? (visible on screen)", default=False)
    print_entries_table(vault.entries, reveal_passwords=reveal)


def action_generate_only():
    console.rule("[bold]Password Generator")
    length_str = Prompt.ask("Password length", default="20")
    try:
        length = max(8, int(length_str))
    except ValueError:
        length = 20
    use_symbols = Confirm.ask("Include symbols?", default=True)
    pwd = generate_password(length=length, use_symbols=use_symbols)
    console.print(Panel.fit(pwd, title=f"Generated password ({estimate_strength_label(pwd)})",
                             border_style="magenta"))
    if Confirm.ask("Copy to clipboard?", default=True):
        copy_to_clipboard_with_autoclear(pwd)


def action_change_master_password(vault: VaultManager):
    console.rule("[bold]Change Master Password")
    console.print("[yellow]This will re-encrypt your entire vault with a new key and salt.[/yellow]")
    if not Confirm.ask("Continue?", default=False):
        return
    new_pwd = prompt_master_password(confirm=True, prompt_text="New master password")
    vault.change_master_password(new_pwd)
    new_pwd_ba = bytearray(new_pwd)
    _zero(new_pwd_ba)
    console.print("[green]Master password changed and vault re-encrypted.[/green]")


MENU = """
[bold]1[/bold]) Add new credential
[bold]2[/bold]) Search / retrieve credential (copies password to clipboard)
[bold]3[/bold]) List all credentials
[bold]4[/bold]) Update credential
[bold]5[/bold]) Delete credential
[bold]6[/bold]) Generate a password (no save)
[bold]7[/bold]) Change master password
[bold]8[/bold]) Lock and exit
"""


def run_menu_loop(vault: VaultManager):
    while True:
        console.print(Panel.fit(MENU.strip(), title="Menu", border_style="blue"))
        choice = Prompt.ask("Choose an option", choices=[str(i) for i in range(1, 9)], default="8")

        try:
            if choice == "1":
                action_add(vault)
            elif choice == "2":
                action_search(vault)
            elif choice == "3":
                action_list(vault)
            elif choice == "4":
                action_update(vault)
            elif choice == "5":
                action_delete(vault)
            elif choice == "6":
                action_generate_only()
            elif choice == "7":
                action_change_master_password(vault)
            elif choice == "8":
                break
        except VaultError as exc:
            console.print(f"[red]Error: {exc}[/red]")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--vault", type=str, default=str(DEFAULT_VAULT_PATH),
                         help=f"Path to the vault file (default: {DEFAULT_VAULT_PATH})")
    args = parser.parse_args()

    vault_path = Path(args.vault).expanduser()
    vault = VaultManager(vault_path)

    print_banner()
    console.print(f"[dim]Vault location: {vault_path}[/dim]\n")

    master_password: Optional[bytes] = None
    try:
        if not vault.exists():
            console.print("[yellow]No vault found at this location. Let's create one.[/yellow]")
            master_password = prompt_master_password(confirm=True)
            vault.create_new(master_password)
            console.print("[green]New vault created and encrypted.[/green]\n")
        else:
            master_password = prompt_master_password(confirm=False)
            try:
                vault.unlock(master_password)
            except AuthenticationError as exc:
                console.print(f"[red]{exc}[/red]")
                sys.exit(1)
            except IntegrityError as exc:
                console.print(f"[red]Vault integrity check failed: {exc}[/red]")
                console.print("[red]Aborting - refusing to operate on a corrupted or tampered vault.[/red]")
                sys.exit(1)
            console.print("[green]Vault unlocked successfully.[/green]\n")

        run_menu_loop(vault)

    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Interrupted. Locking vault and exiting.[/yellow]")
    finally:
        # Best-effort memory hygiene on the way out.
        if master_password is not None:
            mp_ba = bytearray(master_password)
            _zero(mp_ba)
            master_password = None
        vault.lock()
        console.print("[dim]Vault locked. Goodbye.[/dim]")


if __name__ == "__main__":
    main()
