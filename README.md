<div align="center">

# 🔐 secret-manager

**A local-first, end-to-end encrypted desktop vault for your project secrets and environment variables.**

Built for developers who are tired of plaintext `.env` files scattered across machines.
Master-password protected, recovery-code backed, and it never phones home.

Tauri 2 · Rust · React · TypeScript · SQLite · Argon2id · AES-256-GCM

<img src="docs/screenshots/main.png" alt="secret-manager main window" width="900" />

</div>

---

## Why

`.env` files are plaintext, easy to leak, and a pain to share or move between machines.
secret-manager keeps your secrets in a single encrypted vault, organized by project, searchable, and unlocked by one master password — with recovery codes so a forgotten password isn't the end of the world.

## Features

- 🔒 **Encrypted at rest** — every secret value sealed with AES-256-GCM; the key is derived from your master password with Argon2id (64 MB, t=3, p=4) and lives in memory only.
- 🗝️ **Master-password recovery** — single-use recovery codes can reset a forgotten password without re-encrypting anything (envelope encryption).
- 📁 **Projects, secrets & tags** — group secrets per project, tag them, copy with auto-clearing clipboard.
- 🔎 **Global search (⌘K)** — a command palette that searches across *all* projects, both project names and secrets.
- 📦 **Export / import** — back up to plaintext **JSON** or an encrypted, passphrase-protected **vault file** (`.smvault`); export the whole vault or a single project (right-click a project, or use its header).
- ⏱️ **Auto-lock & clipboard auto-clear** — configurable inactivity lock; copied values wiped after a timeout.
- 🌗 **Dark / light / system theme**, show-password toggles, keyboard-first.
- 🖥️ **Cross-platform** — macOS, Windows, Linux from one Rust + web codebase.

## Screenshots

| Unlock / recovery | Global search (⌘K) |
|---|---|
| <img src="docs/screenshots/unlock.png" width="430" /> | <img src="docs/screenshots/command-palette.png" width="430" /> |

| Settings | Encrypted export |
|---|---|
| <img src="docs/screenshots/settings.png" width="430" /> | <img src="docs/screenshots/export.png" width="430" /> |

## Security model

- The master password is **never stored**. A random 32-byte **master key** encrypts every secret value. That master key is *wrapped* (envelope encryption) by:
  - a key derived from your **master password** via **Argon2id**, and
  - a key derived from each **recovery code**.
- **Unlock** derives the password key and decrypts the master-key wrap. **Changing the password** or **recovering** only re-wraps the master key — secrets are never re-encrypted.
- Secret values use **AES-256-GCM** (`ring`), layout `nonce(12) || ciphertext || tag`; tampering fails authentication.
- The master key is **zeroized** on lock. Project names, secret keys, and tags are stored in plaintext (field-level encryption) — see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the threat model.

> ⚠️ **Recovery codes** are shown once at vault creation (and on regenerate). Each works one time. Without the password **and** without a recovery code, a vault cannot be decrypted — there is no backdoor.
>
> ⚠️ **JSON export** contains secret values in **plaintext**. Prefer the encrypted **vault file** for backups you keep around; store any plaintext export securely.

## Backup, recovery & transfer

- **Forgot your password?** Unlock screen → *Forgot your password?* → enter a recovery code → set a new password.
- **Export** — Settings → *Backup & transfer* → *Export all* (choose JSON or encrypted vault file). Single project: its page header, or right-click it in the sidebar.
- **Import** — Settings → *Import*, or the sidebar **Import** button. Encrypted files prompt for the passphrase; duplicate keys resolved by *skip* / *overwrite*.

## Quick start

```bash
# Prerequisites: Rust (stable), Node.js 20+, platform webview deps
#   macOS: bundled · Linux: WebKitGTK · Windows: WebView2
npm install
npm run tauri dev      # launch the desktop app with hot reload
```

First launch prompts you to **create a vault** and **save recovery codes**. After that you get the unlock screen.

### Build installers

```bash
npm run tauri build    # native installers in src-tauri/target/release/bundle
```

## Test

```bash
cd src-tauri && cargo test   # Rust: crypto, vault + recovery, repo CRUD,
                             #       export/import (JSON + encrypted), persistence
npm test                     # Frontend: vitest (utils, stores, components)
npm run typecheck            # tsc --noEmit
```

## Architecture

```
src-tauri/src/
  crypto.rs    Argon2id KDF + AES-256-GCM encrypt/decrypt
  vault.rs     create / unlock / change-password / recovery (envelope encryption)
  repo.rs      projects / secrets / tags CRUD + search
  transfer.rs  export / import bundle — plaintext JSON + encrypted vault file
  db.rs        SQLite open, pragmas, versioned migrations
  state.rs     session state (master key behind a Mutex, zeroized on lock)
  commands/    IPC: vault.rs, projects.rs, secrets.rs, transfer.rs
src/
  lib/         typed invoke() wrappers, types, clipboard, transfer flows
  store/       Zustand: vault (session), settings (persisted), ui (palette)
  components/  Sidebar, SecretList, SecretDetail, UnlockScreen, CommandPalette,
               RecoveryCodes, TransferDialogs, …
  pages/       Home, Project, Settings
```

> The IPC commands behind Argon2id (unlock, create, change-password, recover,
> encrypted export/import) are `async` so the heavy key derivation runs off the
> UI thread — button spinners and loading state stay responsive.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for encryption detail and [docs/ROADMAP.md](docs/ROADMAP.md) for what's next (team sync, `.env` import/export, secret history).

## License

See [LICENSE](LICENSE).
