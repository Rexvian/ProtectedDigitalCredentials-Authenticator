# PDC Authenticator

**Protected Digital Credentials**

[![Version](https://img.shields.io/badge/version-1.1.0-blue)]()
[![Manifest](https://img.shields.io/badge/manifest-v3-green)]()
[![License](https://img.shields.io/badge/license-MIT-yellow)]()

PDC Authenticator is a browser extension that enhances account security by generating time-based one-time passwords (TOTPs) for multi-factor authentication (MFA). It provides a convenient way to manage authentication codes directly in your browser.

**Privacy-first by design:** All authentication data is processed locally on your device, with no cloud synchronization, tracking, or external servers required.

---

## Features

### Authentication
- **TOTP Generation** — Generate time-based one-time passwords using the TOTP standard (RFC 6238).
- **Six-Digit Verification Codes** — Generate temporary authentication codes for supported accounts.
- **Automatic Code Refresh** — Refresh codes according to the configured time interval.

### Security and Privacy
- **AES-256-GCM Encryption** — Encrypt stored account secrets.
- **Master Password Protection** — Protect access to your accounts with a master password.
- **PBKDF2 Key Derivation** — Derive an encryption key from your master password.
- **Automatic Locking** — Lock the extension after a configurable period of inactivity.
- **Manual Locking** — Lock the extension immediately using `Ctrl+L`.
- **Local-Only Processing** — Keep authentication operations on your device.

### Account Management
- **Add and Edit Accounts** — Create accounts, rename them, update secrets, and add descriptions.
- **Delete Accounts** — Remove accounts you no longer need.
- **Drag-and-Drop Reordering** — Organize accounts to suit your preferences.
- **Account Count Visibility** — Choose whether to display the total number of accounts while locked.

### Backup and Recovery
- **JSON Backup and Export** — Export account information and descriptions.
- **Backup Import** — Restore accounts using Replace, Merge, or Cancel options.
- **Recovery Questions** — Use configured recovery questions to recover access if you forget your master password.

### User Experience
- **Dark Interface** — A clean, modern interface designed for comfortable use.
- **Clipboard Integration** — Copy authentication codes with a single click.
- **Keyboard Shortcuts** — Use supported shortcuts for common actions.
- **Cross-Browser Support** — Designed for Chrome, Microsoft Edge, Firefox, and Opera.

---

## How It Works

PDC Authenticator uses the Time-Based One-Time Password (TOTP) algorithm defined in [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238).

1. **Secret Storage:** Account secrets are encrypted using AES-256-GCM before being stored locally.
2. **Key Derivation:** PBKDF2 derives an encryption key from the user's master password using the configured iteration count.
3. **Decryption:** When the extension is unlocked, account secrets are decrypted in memory as needed.
4. **Code Generation:** The extension generates authentication codes using HMAC-SHA1 and the current time counter.
5. **Automatic Refresh:** Codes refresh according to the configured time interval.

All authentication operations are designed to run locally within the browser. The extension does not require an external authentication server.

---

## Installation

### Chrome, Microsoft Edge, and Opera

1. Clone or download this repository.
2. Open the browser's extension management page:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Opera: `opera://extensions/`
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose the directory containing the extension's `manifest.json` file.
6. Pin PDC Authenticator to your toolbar for convenient access.

### Firefox

1. Open `about:debugging#/runtime/this-firefox`.
2. Select **Load Temporary Add-on**.
3. Choose the extension's `manifest.json` file.

> **Note:** Temporary Firefox add-ons are removed when the browser closes. For permanent distribution, the extension must meet Mozilla's requirements and be signed through [Firefox Add-ons](https://addons.mozilla.org/).

---

## Quick Start

### 1. Initial Setup

1. Click the PDC Authenticator icon in your browser toolbar.
2. Create a master password.
3. Configure the three recovery questions.
4. Complete the setup to access the main screen.

### 2. Add an Account

1. Enter an account name, such as `Google` or `GitHub`.
2. Enter the account's Base32-encoded TOTP secret provided during two-factor authentication setup.
3. Select **Add**.
4. Your authentication code will appear in the account list.

### 3. Use an Authentication Code

1. Locate the account you want to authenticate with.
2. Click the copy icon beside the current code.
3. Paste the code into the service's verification field.
4. Complete verification before the code expires.

**Important:** Never share your TOTP secret, master password, recovery answers, or exported backup with anyone.

---

## Usage Guide

### Main Interface

| Element | Description |
|---|---|
| Account List | Displays configured accounts and their current TOTP codes. |
| Copy | Copies the current authentication code to the clipboard. |
| Edit | Allows account names, secrets, and descriptions to be updated. |
| Delete | Removes an account from the extension. |
| Drag Handle | Reorders accounts in the list. |
| Settings | Opens the extension's configuration panel. |
| Test | Adds a test account, if supported by the current implementation. |
| Lock | Immediately locks the extension. |

### Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Enter` | Submits a form or advances to the next field, where supported. |
| `Ctrl+L` | Locks the extension. |
| `Escape` | Closes a modal or returns to the previous view, where supported. |

### Settings

#### Automatic Locking

- **Enabled:** Automatically locks the extension after the configured inactivity period.
- **Disabled:** Disables automatic locking; manual locking remains available.
- **Timeout:** Configure the inactivity period from 30 seconds to 60 minutes.

#### Account Count Visibility

- **Show:** Displays the total number of configured accounts while locked.
- **Hide:** Conceals the count while the extension is locked.

---

## Backup and Restore

### Exporting a Backup

The export feature creates a JSON file containing account information and descriptions.

Example backup structure:

```json
{
  "version": "2.0",
  "timestamp": "2024-01-15T10:30:45.123Z",
  "accounts": {
    "Google": {
      "secret": "JBSWY3DPEHPK3PXP",
      "description": "Personal account"
    },
    "GitHub": {
      "secret": "JBSWY3DPEHPK3PXP",
      "description": "Work"
    }
  },
  "accountCount": 2,
  "type": "auth_accounts_backup"
}
```

The secrets shown above are illustrative examples, not real account credentials.

### Importing a Backup

When importing a backup, choose the appropriate action:

- **Replace:** Replace the existing account list with the imported accounts.
- **Merge:** Combine imported accounts with existing accounts, according to the extension's import rules.
- **Cancel:** Cancel the import operation.

> **Security warning:** Exported backups may contain unencrypted TOTP secrets. Store backup files securely, avoid uploading them to public repositories, and delete temporary copies when they are no longer needed.

---

## Security Considerations

PDC Authenticator is designed with local data processing and encrypted secret storage in mind. However, the actual level of protection depends on the implementation and configuration.

Recommended security practices include:

- Use a strong, unique master password.
- Use a cryptographically secure random salt and initialization vector (IV).
- Configure PBKDF2 with an appropriate iteration count for the target environment.
- Never store the master password or plaintext TOTP secrets persistently.
- Protect recovery mechanisms against unauthorized password resets.
- Keep browser permissions to the minimum required.
- Avoid exposing authentication secrets through logs, error messages, or debugging output.
- Keep the browser and extension updated.
- Store exported backups securely.

**Recovery note:** Recovery questions should not bypass encryption without a secure recovery design. If the encryption key is derived from the master password, resetting that password alone will not decrypt existing data unless a separate recovery mechanism has been implemented.

---

## Technical Standards

| Standard | Purpose |
|---|---|
| RFC 6238 | Defines Time-Based One-Time Password (TOTP) generation. |
| RFC 4226 | Defines the HMAC-Based One-Time Password (HOTP) algorithm underlying TOTP. |
| AES-256-GCM | Provides authenticated encryption for stored secrets. |
| PBKDF2 | Derives an encryption key from a password. |
| Manifest V3 | Provides the extension platform architecture for supported browsers. |

---

## Project Information

- **Project Name:** PDC Authenticator
- **Full Name:** Protected Digital Credentials
- **Project Type:** Browser Extension
- **Category:** Cybersecurity and Multi-Factor Authentication
- **Version:** 1.1.0
- **License:** MIT

---

## License

This project is licensed under the MIT License. See the `[LICENSE](https://github.com/Rexvian/PDC-Authenticator-Protected-Digital-Credentials-/blob/main/LICENCE)` file for details.

---

**PDC Authenticator — Secure access. Verified identity.**
