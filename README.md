# 🔑 mypwd - Terminal Password Manager

Secure, terminal-based password manager with Fernet authenticated encryption for Linux and macOS.

## Features

- **Fernet authenticated encryption** (AES-128-CBC + HMAC-SHA256)
- **scrypt key derivation** (memory-hard) with configurable parameters
- **Master password protection** - one password to access all stored passwords
- **Local storage** - passwords stored in `~/.mypwd/`
- **Username tracking** - store usernames together with passwords for each tag
- **Clipboard integration** - optional copy to clipboard on explicit request
- **Simple CLI interface**
- **Cross-platform** - works on Linux and macOS

## Requirements

- Python 3.6+
- cryptography
- pyperclip

### Platform-Specific Requirements

**Linux:**
- Clipboard support requires `xclip` or `xsel`
- Ubuntu/Debian: `sudo apt-get install xclip`
- Fedora/RHEL: `sudo yum install xclip`
- Arch: `sudo pacman -S xclip`

**macOS:**
- Clipboard support built-in (uses `pbcopy`)
- Homebrew recommended for easier installation

## Installation

```bash
./install.sh
```

The installer will:
1. Detect your OS (Linux or macOS)
2. Install Python dependencies
3. Check for clipboard utilities
4. Create symlink in `~/.local/bin`
5. Provide shell configuration instructions if needed

### Post-Installation

If `~/.local/bin` is not in your PATH, add this to your shell config:

**macOS (zsh):**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

**macOS (bash):**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile
source ~/.bash_profile
```

**Linux:**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## Usage

### Add a password
```bash
mypwd --add github --username octocat
```
You will be prompted securely for the entry password.  
To provide it non-interactively:
```bash
printf '%s\n' 'mySecureP@ssw0rd' | mypwd --add github --username octocat --password-stdin
```
The username/password pair is encrypted and saved together so it is easy to retrieve both later.

### Get password (copy to clipboard)
```bash
mypwd --get github --clipboard
```
Outputs the username and copies the password to your clipboard.

### Get password (output to terminal)
```bash
mypwd --get github --output
```
Prints both the username and password without touching the clipboard.

### Get username only (default)
```bash
mypwd --get github
```
Prints only the username and does not copy the password unless you pass `--clipboard`.

### List all stored tags
```bash
mypwd --list
```

## How it works

1. **Master password**: On first use, you create a master password. This password is used to encrypt all stored passwords.

2. **Encryption**: Passwords are encrypted using Fernet authenticated encryption (AES-128-CBC + HMAC-SHA256). The encryption key is derived from your master password using scrypt.

3. **Storage**: Encrypted `username:password` strings are stored in `~/.mypwd/passwords.enc` and the salt in `~/.mypwd/salt`.

4. **Security**: The master password is never stored. Only the salt (used for key derivation) is stored on disk.

### KDF tuning

You can tune scrypt settings through environment variables before running `mypwd`:

- `MYPWD_SCRYPT_N` (default: `32768`, must be a power of two)
- `MYPWD_SCRYPT_R` (default: `8`)
- `MYPWD_SCRYPT_P` (default: `1`)

Existing databases created with legacy PBKDF2 salt format remain readable for backward compatibility.

## Security notes

- Never share your master password
- Choose a strong master password (12+ characters, mixed case, numbers, symbols)
- The password file is encrypted, but protect your system from unauthorized access
- Back up `~/.mypwd/` periodically if you want to preserve your passwords
- Keep `passwords.enc` and `salt` together during backups/restores; `mypwd` refuses to run if the database exists without its salt metadata
- Database and salt metadata updates use atomic replace writes to reduce corruption risk on interruptions
- If you forget the master password, there's no recovery - you'll lose all stored passwords

## File locations

- **Password database**: `~/.mypwd/passwords.enc`
- **Salt file**: `~/.mypwd/salt`
- **Permissions**: `~/.mypwd` is enforced as `0700`; stored files are enforced as `0600`

## Uninstallation

```bash
rm ~/.local/bin/mypwd
rm -rf ~/.mypwd
pip3 uninstall cryptography pyperclip
```

## License

MIT
