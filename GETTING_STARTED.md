# Getting Started with YubiKey Init

This guide walks you through setting up hardware-backed GPG keys on your YubiKey using `yubikey-init`. By the end, you'll have:

- A master GPG key safely backed up on encrypted storage
- Subkeys (sign, encrypt, authenticate) loaded on your YubiKey
- SSH authentication via your YubiKey
- A backup you can use to provision additional YubiKeys

**Time required:** 15-30 minutes

---

## What You'll Need

### Hardware

| Item | Purpose | Notes |
|------|---------|-------|
| **YubiKey 5 series** | Stores your GPG subkeys | Any model: 5 NFC, 5C, 5Ci, 5C NFC |
| **USB drive or SD card** | Encrypted backup storage | Minimum 100MB, will be reformatted |
| **Your computer** | Running the setup | macOS 12+ or Ubuntu 22.04+ |

### Software

The tool will check these automatically, but here's how to install them:

**macOS:**
```bash
brew install gnupg yubikey-manager
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt install gnupg2 yubikey-manager pcscd scdaemon
sudo systemctl enable --now pcscd
```

### Information to Decide Beforehand

You'll be prompted for these during setup:

| Prompt | Example | Tips |
|--------|---------|------|
| **Identity** | `Jane Doe <jane@example.com>` | Use your real name and primary email |
| **Master passphrase** | `correct-horse-battery-staple` | 12+ characters, memorable, WRITE IT DOWN |
| **YubiKey User PIN** | `123456` (6+ digits) | For daily use (3 wrong attempts locks it) |
| **YubiKey Admin PIN** | `12345678` (8+ digits) | For management (3 wrong attempts bricks OpenPGP) |

---

## Quick Start

### 1. Verify Your Setup

```bash
yubikey-init doctor
```

You should see:
- GnuPG: Installed (2.2+)
- YubiKey Manager: Installed
- Devices Found: Your YubiKey serial number
- Status: "All checks passed"

### 2. Check Connected Devices

```bash
yubikey-init devices
```

This shows your YubiKeys with their current state (keys loaded, PIN status, etc.).

**Tip:** For an interactive view, use `yubikey-init manage` to launch the TUI.

### 3. Start the Workflow

```bash
yubikey-init new
```

The tool will guide you through 7 phases. You can interrupt at any time with `Ctrl+C` and resume later with `yubikey-init continue`.

---

## The 10 Steps

When you run `yubikey-init new`, you'll go through these steps:

### Step 1: Verifying Environment

Checks that GPG, ykman, and smartcard services are working.

```
Step 1: Verifying Environment

  PASS GnuPG: Found gpg (GnuPG) 2.4.9
  PASS YubiKey Manager: Found ykman 5.8.0
  PASS Smartcard Daemon: macOS has built-in smartcard support
  PASS YubiKey Detection: Found 3 YubiKey(s)
  WARN Network Isolation: Network may be active
       Fix: Consider disabling network during key generation
  WARN Paperkey: paperkey not installed (optional)
       Fix: brew install paperkey

All critical checks passed.
```

**If something fails:** The tool shows exactly what to install or fix.

---

### Step 2: Configure Identity

Enter your name and email for the GPG key.

```
Step 2: Configure Identity

Full name (): Jane Doe
Email address (): jane@example.com

Identity: Jane Doe <jane@example.com>
```

---

### Step 3: Set Master Key Passphrase

Create a strong passphrase for your master key.

```
Step 3: Set Master Key Passphrase

Master key passphrase: ****
Confirm passphrase: ****

Passphrase strength: STRONG
```

**Tips:**
- 12+ characters minimum
- Mix of words, numbers, symbols
- Memorable but not guessable
- **Write it down** and store securely

---

### Step 4: Set Up Encrypted Backup Storage

Formats your USB drive with encrypted + public partitions.

```
Step 4: Set Up Encrypted Backup Storage

Available removable drives:
  [1] SanDisk Ultra (15.9 GB) - /dev/disk6
  [2] Enter path manually

Select drive [1-2]: 1

WARNING: This will ERASE ALL DATA on SanDisk Ultra.
Type 'SanDisk Ultra' to confirm: SanDisk Ultra

Creating encrypted backup drive...
  Partitioning .................. OK
  Creating APFS container ....... OK

Enter backup passphrase: ****
Confirm passphrase: ****

  Creating encrypted volume ..... OK
  Creating public volume ........ OK
```

**Important:** Remember this backup passphrase! It's different from your master key passphrase.

---

### Step 5: Generate Master Key

Creates your GPG master (certify-only) key.

```
Step 5: Generate Master Key

Generating ed25519 master key...
  Key ID: 0xABCD1234EFGH5678 .... OK
  Fingerprint: 4E2C 1FA3 372C BA96 ...
```

---

### Step 6: Generate Subkeys

Creates three subkeys for daily use.

```
Step 6: Generate Subkeys

Generating subkeys (expire in 2 years)...
  Signature subkey .............. OK
  Encryption subkey ............. OK
  Authentication subkey ......... OK
```

---

### Step 7: Create Backup

Copies all key material to your encrypted backup drive.

```
Step 7: Create Backup

Mounting encrypted volume...
Copying keys to backup...
  master-key.asc ................ OK
  subkeys.asc ................... OK
  public-key.asc ................ OK
  revocation-cert.asc ........... OK
  GNUPGHOME directory ........... OK
Creating manifest with checksums.. OK
Unmounting backup drive ......... OK
```

---

### Step 8: Verify Backup

**Critical checkpoint** - verify your backup is readable before proceeding.

```
Step 8: Verify Backup

BACKUP VERIFICATION REQUIRED

Before continuing, please:
  1. Remove the backup drive
  2. Re-insert it
  3. Unlock the encrypted partition
  4. Verify the files are readable

Files that should be present:
  - master-key.asc
  - subkeys.asc
  - public-key.asc
  - revocation-cert.asc

Have you verified the backup is readable? [y/N]: y
```

**Do not skip this!** If something goes wrong later, this backup is your only recovery option.

---

### Step 9: Provision YubiKey

Prepares and loads keys onto your YubiKey.

```
Step 9: Provision YubiKey

Select YubiKey to provision:
  [1] YubiKey 5 NFC (13378924) - No keys
  [2] YubiKey 5Ci (14414276) - Has keys

Select [1-2]: 1

Resetting OpenPGP applet ....... OK
Enabling KDF ................... OK

Enter new User PIN (6+ digits): ****
Confirm PIN: ****

Enter new Admin PIN (8+ digits): ****
Confirm PIN: ****

Setting PINs ................... OK

Touch policy for signature key:
  [1] Always require touch (most secure)
  [2] Cached for 15 seconds
  [3] Never require touch
Select [1-3]: 1

Transferring keys to YubiKey...
  Signature key ................. OK (touch YubiKey)
  Encryption key ................ OK (touch YubiKey)
  Authentication key ............ OK (touch YubiKey)
```

---

### Step 10: Remove Master Key from Local Keyring

Removes the master key from your computer (it stays on backup only).

```
Step 10: Remove Master Key from Local Keyring

The master key will be removed from your local keyring.
It will remain ONLY on your encrypted backup drive.

Proceed? [y/N]: y

Removing master key ............ OK
Verifying key stubs ............ OK

Setup Complete!

Key ID: 0xABCD1234EFGH5678
YubiKey: 13378924

Your SSH public key: ~/.ssh/id_yubikey.pub

IMPORTANT:
  1. Store backup drive in secure location
  2. User PIN: 3 wrong attempts locks daily use
  3. Admin PIN: 3 wrong attempts bricks OpenPGP

Provision another YubiKey? [y/N]:
```

---

## After Setup

### Interactive Management

For ongoing device and key management, use the interactive TUI:

```bash
yubikey-init manage
```

This launches a keyboard-driven interface where you can:
- View all connected YubiKeys and their status
- Inspect GPG keys in your keyring
- Run system diagnostics
- Perform operations like reset, label, and protect

**Keyboard shortcuts:**
- `D` - Device list
- `K` - Key list
- `X` - Diagnostics
- `Enter` - View details / Select
- `L` - Set label (on device)
- `R` - Reset device (with confirmation)
- `Escape` - Go back
- `Q` - Quit

### Daily Usage

**Sign a file:**
```bash
gpg --sign document.txt
# Touch YubiKey when it blinks
```

**Encrypt to yourself:**
```bash
gpg --encrypt --recipient 0xABCD1234 document.txt
```

**SSH to a server:**
```bash
# Add your public key to ~/.ssh/authorized_keys on the server
ssh user@server
# Touch YubiKey when it blinks
```

**Check YubiKey status:**
```bash
gpg --card-status
```

### If You Lose Your YubiKey

1. **Don't panic** - Your master key is safe on the backup drive
2. Get your backup drive and a new YubiKey
3. Run: `yubikey-init backup restore /path/to/backup`
4. Run: `yubikey-init new --skip-storage --backup-path /path/to/backup`
5. Provision the new YubiKey

### If You Forget Your PIN

**User PIN locked (3 wrong attempts):**
```bash
# Use Admin PIN to reset
ykman openpgp access unblock --admin-pin 12345678 --new-pin 123456
```

**Admin PIN locked (3 wrong attempts):**
The OpenPGP applet is bricked. You'll need to:
1. Reset the YubiKey: `yubikey-init devices reset <serial>`
2. Re-provision from backup

---

## Troubleshooting

### "No YubiKey detected"

1. Try a different USB port
2. Check `ykman list` - does it show your device?
3. On Linux: Is `pcscd` running? (`sudo systemctl status pcscd`)

### "Card error" or "Smartcard not available"

```bash
# Restart GPG agent
gpgconf --kill all
gpg --card-status
```

### "Operation cancelled by user"

The workflow was interrupted. Resume with:
```bash
yubikey-init continue
```

### "Permission denied" on Linux

```bash
# Add yourself to the plugdev group
sudo usermod -aG plugdev $USER
# Log out and back in
```

### Need More Help?

```bash
# Run full diagnostics
yubikey-init doctor

# Check workflow state
yubikey-init status

# See all commands
yubikey-init --help
```

---

## Security Notes

### What's Protected

| Secret | Where It Lives | Access Required |
|--------|----------------|-----------------|
| Master key | Encrypted backup drive only | Backup passphrase |
| Subkeys | YubiKey only | User PIN + physical touch |
| Private operations | Require YubiKey present | PIN + touch |

### What's Safe to Share

- Your **public key** (`public-key.asc`)
- Your **SSH public key** (`~/.ssh/id_yubikey.pub`)
- Your **key ID** (e.g., `0xABCD1234`)

### What to Keep Secret

- Master passphrase (memorize or store in password manager)
- Backup drive passphrase
- YubiKey PINs
- The backup drive itself (store offline in secure location)

---

## Next Steps

- **Publish your public key** to a keyserver or your website
- **Set up a backup YubiKey** (run workflow again, selecting second YubiKey)
- **Configure git** to sign commits: `git config --global user.signingkey 0xABCD1234`
- **Enable SSH agent** forwarding for remote access
