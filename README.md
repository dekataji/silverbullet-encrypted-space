# Encrypted Space 🔒

End-to-end encrypted notes for [SilverBullet](https://silverbullet.md) (v2).

Notes are stored as `*.enc.md` files with **randomized basenames** — the content is
**AES-256-GCM** ciphertext (key from **PBKDF2-SHA256, 600,000 iterations**).
The server, the git repo, and anyone holding them **cannot read your notes without the
master password**. Unlock once per browser session and all encrypted notes are decrypted
into session memory **plus the browser-side index**, so SilverBullet's native queries
(tasks, etc.) keep working.

## Install

Copy `encrypted-space.plug.js` anywhere into your space (e.g. `Library/`), then run
**`Plugs: Reload`** from the command palette.

Or install as a library page: copy `libraries/EncryptedSpace.md` into your space's
`Library/` folder (it pulls the bundled plug).

## Commands

| Command | What it does |
|---|---|
| **Encrypted Space: Unlock** | Enter the master password once per session. Decrypts all `*.enc.md` into memory and indexes their tasks so native queries work. |
| **Encrypted Space: Lock** | Wipes session memory and clears the index. Also happens automatically when the browser tab closes. |
| **Encrypted Space: New note** | Creates a new encrypted note (random filename) and opens the editor. |
| **Encrypted Space: Open note** | Pick an encrypted note from a list of decrypted titles, view read-only. |
| **Encrypted Space: Edit note** | Pick a note, edit in a modal, **Save (encrypt)**. Encryption happens in your browser via WebCrypto; the ciphertext is written with `PUT /.fs/…` — plaintext never touches the server. |
| **Encrypted Space: Convert current note to encrypted** | Encrypts the currently open regular note into a random `*.enc.md` in the same folder, then asks whether to delete the original. |

## Security model

- **Threat model:** anyone with the git repo or server access cannot read notes without
  the master password. Plaintext exists only in your browser's memory while unlocked.
- **What is hidden:** note bodies *and* titles/filenames (random basenames; the real
  title lives inside the encrypted envelope).
- **What is not hidden:** file sizes, count of encrypted notes, modification times.
- **Lost password = lost data.** There is no recovery. The password is never written to disk.
- **Browser-profile caveat:** while unlocked, decrypted objects live in the browser's
  IndexedDB index; `Lock` clears them, but IndexedDB deletion is not forensic erasure —
  someone with your device could theoretically recover traces. The server/repo side stays clean.
- **Git history:** encrypting now does not erase old plaintext commits. Purge them
  (`git filter-repo` + force push) if sensitive notes were committed in plaintext before.
- Keep SilverBullet's **Runtime API disabled** (it would index files server-side — as
  ciphertext only, but off is cleaner).
- The password prompt echoes plaintext — beware shoulder surfing.

## How it works

- Single-file plug (`encrypted-space.plug.js`), hand-built bundle following the
  compiled-plug worker protocol (`manifest` + `syscall` bridge), no build step, no dependencies.
- Envelope per file: `{"v":1,"salt":b64,"iv":b64,"ct":b64}`, `ct` = AES-GCM of
  `{"title": "…", "body": "…"}`.
- On unlock: `index.clearFileIndex` + `index.indexObjects` per file with decrypted
  **task** objects (`{ref, tag:"task", name, done, page}`) so `${query[[from index.tag "task"]]}` works.
- On lock (or tab close): memory wiped, `index.clearFileIndex` per file.
- A `page:index` event listener re-indexes `.enc.md` files edited via the modal.
- Encrypted notes are intentionally excluded from `page` queries — discover them via
  **Open note** (decrypted titles) after unlock.

## Limitations

- No transparent encrypt-on-save in the Markdown editor (SilverBullet v2 has no
  before-load/before-save plug hooks — see [silverbullet#1978](https://github.com/silverbulletmd/silverbullet/issues/1978)).
  Editing goes through the plug's modal.
- Encrypted notes are not full-text searchable and don't appear in backlinks/page listings.

## License

MIT — see [LICENSE](LICENSE).
