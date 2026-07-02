# secret-manager

Cross-platform desktop app for storing and managing secrets and environment variables. Personal use first, small-team sharing later.

## Tech Stack

| Layer | Choice | Reason |
|---|---|---|
| Backend | Rust (Tauri) | Native performance, excellent crypto crates, small binary |
| Frontend | React + TypeScript + Vite | Type-safe, fast iteration, Tauri ships it as a webview |
| Styling | Tailwind CSS + shadcn/ui | Consistent components, dark-mode ready |
| Database | SQLite via `rusqlite` | Local, embedded, queryable |
| Encryption | `ring` + `argon2` | AES-256-GCM + Argon2id, audited crates |
| State (frontend) | Zustand | Lightweight, no boilerplate |

## Architecture Overview

```
secret-manager/
├── src-tauri/               # Rust backend
│   ├── src/
│   │   ├── main.rs          # Tauri app entry, registers commands
│   │   ├── crypto.rs        # Key derivation (Argon2id) + encryption (AES-256-GCM)
│   │   ├── db.rs            # SQLite init, migrations, raw queries
│   │   ├── vault.rs         # Vault open/close, session key management
│   │   ├── models.rs        # Rust structs: Project, Secret, Tag
│   │   └── commands/        # Tauri IPC command handlers
│   │       ├── mod.rs
│   │       ├── vault.rs     # unlock_vault, lock_vault, change_master_password
│   │       ├── projects.rs  # create_project, list_projects, delete_project
│   │       └── secrets.rs   # add_secret, get_secret, list_secrets, update_secret, delete_secret, search_secrets
│   └── Cargo.toml
├── src/                     # React frontend
│   ├── components/
│   │   ├── ui/              # shadcn/ui base components
│   │   ├── Sidebar.tsx      # Project list navigation
│   │   ├── SecretList.tsx   # Secrets table for a project
│   │   ├── SecretDetail.tsx # View/edit single secret
│   │   └── UnlockScreen.tsx # Master password entry
│   ├── pages/
│   │   ├── Home.tsx
│   │   ├── Project.tsx
│   │   └── Settings.tsx
│   ├── store/
│   │   └── vault.ts         # Zustand store: session state, active project
│   ├── lib/
│   │   └── tauri.ts         # Typed wrappers around Tauri invoke() calls
│   └── main.tsx
├── docs/
│   ├── ARCHITECTURE.md      # Encryption design, DB schema, IPC surface
│   └── ROADMAP.md           # Phased implementation plan
└── CLAUDE.md                # This file
```

## Encryption Design

**Never store the master password.** The vault database itself is encrypted at
rest (full-DB SQLCipher, v3 — see below); pre-unlock metadata needed to derive
the key lives in a plaintext sidecar file, `vault.meta.json`, next to the vault:
1. Argon2id parameters + password salt + recovery salts (KDF inputs)
2. The wrapped master key (password wrap + one wrap per recovery code)
3. A verification blob (to confirm correct password on unlock without opening the DB)
4. Rate-limit state (failed-attempt counter + backoff expiry)
5. An optional macOS Touch ID wrap (see Biometric Unlock below)

**Unlock flow (v3, current):**
```
master_password + pw_salt → Argon2id → pw_key
pw_key → AES-256-GCM decrypt master_wrap → master_key (32 bytes, in memory only)
master_key (hex) → SQLCipher raw key → PRAGMA key on the SQLite connection
```
Once keyed, the entire SQLite file — schema, project names, secret keys/tags,
and secret values — is opaque ciphertext on disk; there is no plaintext
metadata table anymore. The master key is also wrapped by each single-use
**recovery code**, so a code can reset the password without re-encrypting
anything. See `docs/ARCHITECTURE.md` for full detail on the sidecar, SQLCipher
integration, legacy migration, rate limiting, and biometric unlock.

**Argon2id parameters (minimum):**
- `m_cost`: 65536 (64 MB)
- `t_cost`: 3 iterations
- `p_cost`: 4 parallelism
- `salt`: 32 random bytes, generated once per vault, stored in `vault.meta.json`

**Rate limiting:** failed unlock attempts are counted and, past a threshold,
gated by an exponential backoff (persisted in the sidecar so it survives app
restarts). The backoff is temporary and capped — never a permanent lockout.

**macOS Touch ID unlock:** a random token is stored in the macOS Keychain
behind a biometric access-control policy (Secure Enclave); the sidecar holds
`AES-256-GCM(token, master_key)`. Unlock triggers a Touch ID/Face ID prompt to
release the token, which unwraps the master key. Not available on other
platforms.

**Legacy vault migration:** vaults created before v3 (plaintext SQLite with a
`vault_meta` table) are migrated transparently on first unlock: the plaintext
DB is read, verified, and re-exported into a new SQLCipher-encrypted file at
the same path. The original plaintext file is kept as a one-time `<path>.bak`
rather than deleted, so a failed/interrupted migration can't destroy data.
That `.bak` is plaintext — treat it as sensitive; it is removed automatically
if the vault is later deleted via `delete_vault`, but otherwise persists on
disk until manually removed.

## Database Schema

The `vault_meta` table below still exists inside the (now SQLCipher-encrypted)
database, but it only tracks the internal schema/migration version
(`db_version`) — the KDF/wrap/verify/rate-limit/biometric fields it used to
hold pre-unlock now live in the plaintext `vault.meta.json` sidecar instead,
since they must be readable *before* the master key is available to open the
DB. Everything in this schema, including table/column names and all row data,
is only readable once the DB is opened with the derived master key.

```sql
CREATE TABLE vault_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- stores: db_version (schema/migration version only; KDF + wrap state moved
-- to vault.meta.json in v3)

CREATE TABLE projects (
  id          TEXT PRIMARY KEY,   -- UUIDv4
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  INTEGER NOT NULL,   -- Unix timestamp ms
  updated_at  INTEGER NOT NULL
);

CREATE TABLE secrets (
  id              TEXT PRIMARY KEY,
  project_id      TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key             TEXT NOT NULL,
  value_encrypted BLOB NOT NULL,  -- AES-256-GCM ciphertext (nonce prepended)
  description     TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE(project_id, key)
);

CREATE TABLE tags (
  id   TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE secret_tags (
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  tag_id    TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (secret_id, tag_id)
);

CREATE INDEX idx_secrets_project ON secrets(project_id);
CREATE INDEX idx_secret_tags_secret ON secret_tags(secret_id);
CREATE INDEX idx_secret_tags_tag ON secret_tags(tag_id);
```

## Tauri IPC Commands

All commands are async. Errors return a string error message. The frontend calls them via `invoke()`.

### Vault
| Command | Args | Returns |
|---|---|---|
| `vault_exists` | `{ vault_path?: string }` | `bool` |
| `vault_has_recovery` | `{ vault_path?: string }` | `bool` |
| `create_vault` | `{ password: string, vault_path?: string }` | `string[]` (one-time recovery codes) |
| `unlock_vault` | `{ password: string, vault_path?: string }` | `bool` |
| `recover_vault` | `{ code: string, new_password: string, vault_path?: string }` | `void` |
| `regenerate_recovery_codes` | — | `string[]` |
| `delete_vault` | `{ vault_path?: string }` | `void` |
| `lock_vault` | — | `void` |
| `vault_is_unlocked` | — | `bool` |
| `get_vault_path` | — | `string \| null` |
| `change_master_password` | `{ old_password: string, new_password: string }` | `void` |
| `biometric_available` | — | `bool` (platform/device capability, macOS only) |
| `biometric_enrolled` | `{ vault_path?: string }` | `bool` |
| `biometric_enroll` | — | `void` (requires an unlocked vault) |
| `biometric_unlock` | `{ vault_path?: string }` | `bool` (triggers Touch ID/Face ID prompt) |
| `biometric_disable` | `{ vault_path?: string }` | `void` |

> Vaults use full-DB SQLCipher encryption (v3): a random master key encrypts
> the entire SQLite file and is wrapped by the password and by each recovery
> code, with pre-unlock state (KDF params, wraps, verify blob, rate-limit
> counters, biometric wrap) held in a `vault.meta.json` sidecar next to the
> vault. Unlock/recover/change only re-wrap the master key. `unlock_vault`
> transparently migrates a legacy pre-v3 plaintext vault on first use (keeping
> a `.bak`), and enforces exponential backoff after repeated failures (never a
> permanent lockout — see `AppError::RateLimited { retry_after_secs }`).
> See `docs/ARCHITECTURE.md`.

### Projects
| Command | Args | Returns |
|---|---|---|
| `create_project` | `{ name: string, description?: string }` | `Project` |
| `list_projects` | — | `Project[]` |
| `get_project` | `{ id: string }` | `Project` |
| `update_project` | `{ id: string, name?: string, description?: string }` | `Project` |
| `delete_project` | `{ id: string }` | `void` |

### Secrets
| Command | Args | Returns |
|---|---|---|
| `add_secret` | `{ project_id, key, value, description?, tags? }` | `Secret` |
| `get_secret` | `{ id: string }` | `Secret` (value decrypted) |
| `list_secrets` | `{ project_id: string }` | `SecretMeta[]` (value omitted) |
| `update_secret` | `{ id, key?, value?, description?, tags? }` | `Secret` |
| `delete_secret` | `{ id: string }` | `void` |
| `search_secrets` | `{ query: string, project_id?: string, tags?: string[] }` | `SecretMeta[]` |
| `list_tags` | — | `Tag[]` |
| `delete_tag` | `{ id: string }` | `void` |

### Export / Import
| Command | Args | Returns |
|---|---|---|
| `export_all` | `{ path, encrypted: bool, passphrase?: string }` | `void` |
| `export_project` | `{ project_id, path, encrypted: bool, passphrase?: string }` | `void` |
| `import_is_encrypted` | `{ path: string }` | `bool` |
| `import_file` | `{ path, mode?: "skip" \| "overwrite", passphrase?: string }` | `ImportSummary` |

`ImportSummary = { projects_created, projects_merged, secrets_imported, secrets_overwritten, secrets_skipped }`.

Two on-disk formats:
- **JSON** (`format: "secret-manager-export"`) — plaintext bundle.
- **Vault file** (`format: "secret-manager-vault"`, `.smvault`) — the same bundle
  sealed with AES-256-GCM under an Argon2id key derived from a user passphrase.

Import auto-detects the format; encrypted files require `passphrase`. Projects
match by name, secrets by key within a project.

> Argon2id-heavy vault commands (`create_vault`, `unlock_vault`,
> `change_master_password`, `recover_vault`, `regenerate_recovery_codes`) and the
> encrypted export/import commands are `async` so key derivation runs off the
> webview's main thread — otherwise the UI (button spinners/loading) freezes
> during the ~1s derivation.

## Vault File Location

Default: OS-specific app data directory via Tauri's `app_data_dir()`.
- macOS: `~/Library/Application Support/secret-manager/vault.db`
- Linux: `~/.local/share/secret-manager/vault.db`
- Windows: `%APPDATA%\secret-manager\vault.db`

User can override via Settings → Custom vault path. Path stored in Tauri's app config.

Alongside `vault.db` you may also find:
- `vault.db.meta.json` — the sidecar (KDF params, wraps, verify blob,
  rate-limit state, optional biometric wrap). Required to unlock; treat it as
  part of the vault (back it up together with `vault.db`).
- `vault.db.bak` — present only after a legacy vault was migrated to v3 on
  unlock. This is the **original plaintext** database kept as a safety copy;
  it is not needed for normal operation and is deleted automatically if the
  vault is later removed via `delete_vault`. Settings → "Delete plaintext
  backup" removes just the `.bak` once you've confirmed the migrated vault
  works (`migration_backup_exists`/`delete_migration_backup` commands).
- `vault.db-wal` / `vault.db-shm` — normal SQLite WAL-mode files.

## Coding Conventions

### Rust
- Use `thiserror` for error types. Define `AppError` in `error.rs`.
- All Tauri commands return `Result<T, String>` (serialize error to string for frontend).
- Session vault key lives in a `Mutex<Option<[u8; 32]>>` managed via Tauri state.
- Zeroize vault key on `lock_vault` using the `zeroize` crate.
- No `unwrap()` in production paths. Use `?` operator.

### TypeScript / React
- Strict mode TypeScript. No `any`.
- All `invoke()` calls go through typed wrappers in `src/lib/tauri.ts`.
- Components: functional only, hooks for logic.
- Secret values never stored in React state longer than needed (clear on navigation away).

## Key Crates

```toml
[dependencies]
tauri = { version = "2", features = ["shell-open"] }
rusqlite = { version = "0.31", features = ["bundled-sqlcipher-vendored-openssl"] }
ring = "0.17"
argon2 = "0.5"
zeroize = { version = "1", features = ["derive"] }
uuid = { version = "1", features = ["v4"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
base64 = "0.22"
security-framework = "3"   # macOS Keychain + biometric access control (Touch ID)
```

`rusqlite`'s `bundled-sqlcipher-vendored-openssl` feature compiles SQLCipher
(and a vendored OpenSSL for its crypto) into the binary — this is what makes
full-DB encryption (`db::open_keyed`, `PRAGMA key`) possible with no external
SQLCipher/OpenSSL install required. `security-framework` is macOS-only in
practice; `biometric.rs` compiles a no-op stub on other platforms.

Frontend: `@zxcvbn-ts/core` (+ `language-common`/`language-en`) powers the password-strength meter
(`src/lib/passwordStrength.ts`, `src/components/StrengthMeter.tsx`) shown on
create/change/recover. It is advisory only — weak passwords are warned about,
never blocked.

## Future: Team Sharing (Phase 3)

Design for a self-hosted sync server. The local vault is the source of truth until sync is configured.

- Each user has their own local vault.
- Admin configures a server URL + API key in Settings.
- A sync daemon (Tauri background task) pushes encrypted diffs to the server.
- Server stores only ciphertext — it never sees plaintext values.
- Per-project roles: `admin` (CRUD) and `reader` (list + get).
- User identity: simple username + server-issued token (no OAuth complexity for v1).

Schema additions for Phase 3: `users`, `project_members`, `sync_log` tables.

## Development Setup

```bash
# Prerequisites: Rust, Node.js 20+, Tauri CLI
cargo install tauri-cli

# Install frontend deps
npm install

# Run in dev mode
cargo tauri dev

# Build
cargo tauri build
```
