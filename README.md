# Secure Password Manager

A zero-knowledge, local-first CLI password manager written in Python.
All credentials are stored in a single encrypted vault file on your own
machine — nothing is ever sent to a network, and the master password is
never written to disk in any form.

---

## 1. Features

- **Zero-knowledge architecture** — the master password exists only in
  process memory for the duration it's needed; it is never persisted,
  logged, or transmitted anywhere.
- **AES-256-GCM authenticated encryption** — the entire vault (every
  service, username, password, and note) is encrypted as one JSON blob.
  GCM gives you confidentiality *and* tamper detection in a single
  primitive.
- **PBKDF2HMAC-SHA256 key derivation** — 600,000 iterations, unique
  16-byte random salt per vault.
- **Full CRUD** — add, search/retrieve, update, and delete credentials.
- **Clipboard integration** — retrieved passwords are copied to the
  clipboard and automatically cleared after 20 seconds.
- **Built-in secure password generator** — uses Python's `secrets`
  module (CSPRNG), guarantees a mix of upper/lowercase, digits, and
  symbols.
- **Tamper detection** — an incorrect master password or a modified
  vault file both fail the same authenticated-decryption check, and the
  program aborts cleanly without revealing any vault contents.
- **No temp files** — the vault is decrypted straight into memory and
  written back with a single `write()` call; no intermediate files ever
  touch disk.

---

## 2. Setup

### Requirements
- Python 3.10 or later

### Installation

```bash
python3 -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Running

```bash
python3 main.py
```

By default the vault is stored at:

```
~/.secure_password_manager/vault.json
```

You can point to a different location (e.g. for backups, multiple
profiles, or a synced folder) with:

```bash
python3 main.py --vault /path/to/my_vault.json
```

On first run at a given path, you'll be asked to create a master
password (entered twice, hidden input via `getpass`, minimum 8
characters). On every subsequent run, you'll be asked to enter that
same master password to unlock the vault.

---

## 3. Usage

Once unlocked, you get a menu:

```
1) Add new credential
2) Search / retrieve credential (copies password to clipboard)
3) List all credentials
4) Update credential
5) Delete credential
6) Generate a password (no save)
7) Change master password
8) Lock and exit
```

- **Add**: enter a service/URL and username, then either auto-generate a
  strong password or type your own (hidden input). You'll be offered the
  chance to immediately copy the new password to your clipboard.
- **Search / retrieve**: search by service or username substring, pick a
  result from the table, and the password is copied to your clipboard
  (never printed in full to the screen) with a 20-second auto-clear.
- **List**: view all entries; passwords are masked by default and only
  shown in full if you explicitly opt in.
- **Update**: change any field on an existing entry; leave fields as-is
  by accepting the default.
- **Delete**: requires an explicit confirmation prompt.
- **Generate**: a one-off password generator that doesn't touch the
  vault at all — handy for external sign-ups.
- **Change master password**: re-derives a brand-new salt and key and
  re-encrypts the entire vault under it.

---

## 4. Cryptographic design

### 4.1 Key derivation

| Parameter    | Value                                               |
|--------------|------------------------------------------------------|
| Algorithm    | PBKDF2HMAC with SHA-256                              |
| Iterations   | 600,000                                              |
| Salt         | 16 bytes (128-bit), generated with `os.urandom`, unique per vault |
| Output       | 32 bytes (256-bit AES key)                           |

600,000 iterations is in line with current OWASP/NIST-informed guidance
for PBKDF2-SHA256 as of this writing, and is deliberately expensive
enough to make offline brute-force / dictionary attacks against a
stolen vault file costly, while remaining fast enough (well under a
second on typical hardware) for interactive use.

**Why PBKDF2HMAC-SHA256 instead of Argon2id?** Argon2id is generally
the stronger modern choice against GPU/ASIC attackers because it is
memory-hard, and would be the recommended upgrade path (via the
`argon2-cffi` package) for a production deployment. This project uses
PBKDF2HMAC-SHA256 because it ships in the `cryptography` library
specified for this project's tech stack, with no extra native
dependencies. The `CryptoManager.derive_key()` function is the single
place this would need to change to swap in Argon2id.

### 4.2 Encryption

| Parameter     | Value                                             |
|---------------|-----------------------------------------------------|
| Algorithm     | AES-256 in GCM mode (AEAD)                        |
| Nonce         | 12 bytes (96-bit), fresh random value every save   |
| Associated data | none                                              |
| Authentication tag | 16 bytes, appended by the `cryptography` AESGCM implementation |

The **entire vault** (all entries, not per-entry) is serialized to JSON
and encrypted as one blob. A new random nonce is generated on every
single save, which is required for AES-GCM safety since the AES key
itself does not change between saves for a given master password.

### 4.3 Vault file format

```json
{
  "version": 1,
  "kdf": {
    "name": "PBKDF2HMAC-SHA256",
    "iterations": 600000,
    "salt": "<base64, 16 bytes>"
  },
  "nonce": "<base64, 12 bytes>",
  "ciphertext": "<base64, AES-256-GCM ciphertext + 16-byte tag>"
}
```

Everything outside `ciphertext` (version, KDF parameters, salt, nonce)
is intentionally public — none of it is secret, and all of it is
required to reproduce the decryption key and verify the ciphertext.
The vault file is also written with `0o600` permissions where the
filesystem supports it (owner read/write only).

### 4.4 Tamper detection / integrity

AES-GCM's authentication tag means decryption is all-or-nothing: if the
derived key is wrong (bad master password) **or** if a single byte of
`ciphertext`, `nonce`, or the tag has been altered, decryption raises
`InvalidTag` and no plaintext is ever produced. The program treats both
cases identically ("incorrect master password, or vault has been
tampered with") and aborts — this is a deliberate choice to avoid
giving an attacker an oracle that distinguishes "wrong password" from
"corrupted file."

### 4.5 Zero-knowledge handling of the master password

- The master password is read via `getpass.getpass()`, which suppresses
  terminal echo.
- It is converted to `bytes` and fed directly into PBKDF2; it is never
  written to any file, environment variable, log, or config.
- After the key is derived, the local reference to the master password
  bytes is wrapped in a `bytearray`, explicitly overwritten with zeros,
  and released before the program continues — see `_zero()` in
  `main.py`.
- Only the *derived* AES key (not the master password) is kept in
  memory for the duration of the session, and it too is zeroed on lock/exit.

---

## 5. Threat model

### In scope / mitigated
- **Theft of the vault file** (e.g. stolen laptop, leaked backup):
  without the master password, the attacker only has a random-looking
  ciphertext blob. Brute-forcing it requires paying the 600,000-iteration
  PBKDF2 cost for every guess.
- **Tampering with the vault file at rest**: any modification is
  detected by AES-GCM's authentication tag, and the program refuses to
  load a tampered vault.
- **Shoulder-surfing during input**: master password and manually typed
  passwords use `getpass` (hidden input); stored passwords are masked by
  default in list views.
- **Clipboard exposure**: copied passwords are cleared automatically
  after a timeout, reducing the window where they linger in clipboard
  history/managers.

### Explicitly out of scope
- **A compromised endpoint**: if the machine running this tool has a
  keylogger, malware with memory-scraping capability, or a
  malicious/compromised Python interpreter, no purely application-level
  design can fully protect the master password or plaintext secrets
  while they're being typed or processed. This tool assumes the host OS
  and Python runtime are trustworthy.
- **Multi-user / networked use**: there is no sync, sharing, or
  server-side component. This is a single-user, single-machine tool.
- **Physical memory forensics of a live process**: see the memory-safety
  limitations below.
- **Clipboard managers / cloud clipboard sync**: some OS or third-party
  tools persist clipboard history elsewhere; this tool can only clear
  the *live* system clipboard it wrote to.

### Memory-safety limitations (important, please read)
CPython strings (`str`) are immutable and cannot be reliably zeroed out
of memory once created — the interpreter may keep additional copies
around due to string interning, garbage collection timing, or internal
buffers. To reduce (not eliminate) this risk:
- Secrets are handled as `bytes`/`bytearray` wherever feasible, and
  explicitly zeroed with `_zero()` as soon as they're no longer needed.
- Secrets are converted to `str` only at the last moment required by an
  API (e.g. `getpass`, `pyperclip`, JSON serialization), minimizing how
  long an immutable copy can exist.
- This is a **best-effort mitigation**, not a guarantee. For a threat
  model that must defend against forensic memory dumps of a live
  process, a memory-safe language with explicit secure-erase primitives
  (or OS-level facilities like `mlock`/`VirtualLock` plus a hardened
  allocator) would be required — out of scope for this project.

---

## 6. Design notes / trade-offs

- **No temp files, by design**: saves are done with a single
  `Path.write_text()` call rather than the common "write to temp file,
  then atomically rename" pattern. This satisfies the requirement that
  no temporary plaintext-adjacent files are created during reads/updates,
  but it means a save interrupted mid-write (e.g. power loss) could in
  theory leave a corrupted vault file. Regular backups of the vault file
  are recommended as mitigation; a future version could offer an
  opt-in atomic-write mode for users who prefer that trade-off instead.
- **Whole-vault encryption vs. per-entry encryption**: encrypting the
  vault as one blob keeps the design simple and means every save
  re-randomizes the nonce for the entire dataset, but it also means
  every operation decrypts/re-encrypts the full vault (fine for a
  personal password manager's scale — dozens to low thousands of
  entries — but not designed for huge shared datasets).

---

## 7. Project structure

```
.
├── main.py            # Complete CLI application
├── requirements.txt    # Python dependencies
└── README.md           # This file
```
