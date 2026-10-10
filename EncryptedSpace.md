---
tags: [meta, library]
description: Encrypted Space - end-to-end encrypted notes (AES-256-GCM)
---

# Encrypted Space 🔒

Secret notes with real end-to-end encryption: **AES-256-GCM** + **PBKDF2-SHA256 (600k iterations)**.
Stored as `*.enc.md` files (random names, ciphertext content). The server and the GitHub
repo only ever see ciphertext — unreadable without the master password.

## Usage

Run from the command palette (after updating: run **`Plugs: Reload`** once):

1. **Encrypted Space: Unlock** — enter the master password (once per browser session).
   All `*.enc.md` files are decrypted into memory and their tasks indexed, so native
   queries keep working.
2. **Encrypted Space: New note** — create a new encrypted note (opens the editor modal).
3. **Encrypted Space: Open note** — pick a note from the decrypted-title list → read-only view.
4. **Encrypted Space: Edit note** — pick a note → edit in the modal → **Save (encrypt)**.
   Saved directly encrypted from the browser; no plaintext ever touches the server.
5. **Encrypted Space: Convert current note to encrypted** — encrypts the currently open
   regular note (same folder, random name), then asks whether to delete the original.
6. **Encrypted Space: Lock** — locks: memory wiped, index cleared.
   Also locks automatically when the browser tab closes (password lives in session memory only).

## Know this

- **Lost password = lost data.** No recovery. Do not forget it.
- The password prompt echoes plaintext — beware shoulder surfing.
- Encrypted notes don't show in page listings / `page` queries — only their tasks are indexed.
  Find notes via **Open note** (real titles appear after unlock).
- Opening an `.enc.md` file directly shows raw JSON ciphertext — use the commands above.
- `Library/EncryptedSpace/verifier.json` is used to check the password (ciphertext, safe).
- Git history: if a secret note was ever committed in **plaintext**, purge its history
  (filter-repo + force push) — encrypting now doesn't erase old commits.
- Keep the Runtime API disabled — if on, the server only ever sees ciphertext.

## Technical (for debugging)

- Plug: `Library/encrypted-space.plug.js` (hand-built bundle, subtasks.plug.js pattern)
- Source/dev: <https://github.com/dekataji/silverbullet-encrypted-space>
- Per-file keys are derived in the Web Worker; the edit modal encrypts in an iframe via
  WebCrypto and writes with `PUT /.fs/…` — plaintext never hits disk/server.
