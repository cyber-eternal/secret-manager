# Architecture

## Threat Model

What we protect against:
- **Disk theft / unauthorized file access** — vault file is encrypted at rest; useless without master password
- **Memory scraping** — vault key zeroized on lock; secret values cleared from UI state on navigation
- **Weak passwords** — Argon2id with high cost parameters makes brute force expensive

What we do NOT protect against (out of scope for v1):
- Malware with root access on the user's machine
- Compromised Tauri/OS process memory
- Keyloggers capturing the master password

---

## Encryption Layer

### Key Derivation

```
Input:  master_password (UTF-8 string)
        salt (32 random bytes, stored in vault_meta)

Algorithm: Argon2id
  m_cost:  65536  (64 MB memory)
  t_cost:  3      (iterations)
  p_cost:  4      (parallelism)
  hash_len: 32    (256-bit output)

Output: vault_key (32 bytes) — held in memory ONLY, never persisted
```

Argon2id is preferred over Argon2i/Argon2d because it resists both side-channel and GPU attacks.

### Envelope Encryption & Recovery (vault format v2)

New vaults use envelope encryption. A random 32-byte **master key** encrypts all
secret values. The master key is never stored in the clear — it is *wrapped*
(AES-256-GCM) by:

- a key derived from the **master password** (`master_wrap`)
- a key derived from each **recovery code** (the `recovery` list)

```
master_key            = 32 random bytes (memory only)
pw_key                = Argon2id(password, pw_salt)
master_wrap           = AES-256-GCM(pw_key, master_key)
recovery[i].wrap      = AES-256-GCM(Argon2id(code_i, salt_i), master_key)
verify_blob           = AES-256-GCM(master_key, "secret-manager-verify-v1")
secret.value_encrypted= AES-256-GCM(master_key, plaintext)
```

- **Unlock:** derive `pw_key` → decrypt `master_wrap` → master key → verify.
- **Recover:** for each recovery entry, derive its key from the entered code and
  try to decrypt its wrap; on success, re-wrap the master key under a new
  password. 8 single-use codes are generated at creation and shown once.
- **Change password / recover:** only the master-key wrap is rewritten — secret
  values are **not** re-encrypted (the master key is stable).

`vault_meta` (v2) stores: `vault_version=2`, `kdf_params`, `pw_salt`,
`master_wrap`, `recovery` (JSON list of `{salt, wrap}`), `verify_blob`.

**Legacy v1 vaults** (direct password-derived key, no recovery) still unlock; a
v1 password change re-encrypts secrets as before. New vaults are always v2.

### Vault Verification

On first vault creation, store a verification blob so we can confirm the correct password on unlock without decrypting all secrets:

```
verify_plaintext = "secret-manager-verify-v1"
verify_nonce     = random 12 bytes
verify_blob      = AES-256-GCM(vault_key, verify_plaintext, nonce=verify_nonce)
stored           = hex(verify_nonce) + "." + hex(verify_blob)
```

On unlock: derive vault_key → attempt to decrypt verify_blob → success means correct password.

### Secret Value Encryption

Each secret value is independently encrypted:

```
plaintext  = secret value (UTF-8 bytes)
nonce      = random 12 bytes (unique per encryption operation)
ciphertext = AES-256-GCM(vault_key, plaintext, nonce)
stored     = nonce (12 bytes) || ciphertext  (as BLOB in SQLite)
```

AES-256-GCM provides both confidentiality and integrity. Any tampering with the ciphertext will cause decryption to fail with an authentication error.

### Password Change

For a **v2** vault, changing the password only re-derives `pw_key` from the new
password + a fresh `pw_salt` and rewrites `master_wrap`. Secret values are
untouched. Recovery wraps are left intact.

For a **v1** legacy vault, the password change still re-encrypts every secret:
1. Derive `old_vault_key` from old password
2. Derive `new_vault_key` from new password + new salt
3. Decrypt every `value_encrypted` with `old_vault_key`, re-encrypt with the new
4. Update `vault_meta` with new salt + verify_blob — all in one SQLite
   transaction (atomic, no partial state)

### Export / Import

Export serializes projects + decrypted secrets to a portable bundle, either the
whole vault or a single project, in one of two formats:

- **JSON** (`format: "secret-manager-export"`) — plaintext; portability over
  secrecy.
- **Encrypted vault file** (`format: "secret-manager-vault"`, `.smvault`) — the
  same JSON bundle sealed with AES-256-GCM under an Argon2id key derived from a
  user-supplied passphrase. Self-describing envelope: `{ format, version, kdf,
  salt, data }`. Portable across machines/vaults; decryptable only with the
  passphrase.

Import auto-detects the format (`is_encrypted`), prompting for the passphrase
when needed. It matches projects by name (created if missing) and secrets by key
within a project; duplicate keys are resolved by the chosen mode (`skip` |
`overwrite`). Import runs inside a single transaction.

### Threading

The IPC commands that run Argon2id (vault create/unlock/change-password/recover,
recovery-code regeneration, and encrypted export/import) are `async` Tauri
commands. Tauri runs sync commands on the webview's main thread; a ~1s Argon2id
derivation there would block rendering, freezing button spinners and loading
state. Async commands run off the main thread, keeping the UI responsive.

---

## Database Layer

### Engine

`rusqlite` with the `bundled` feature (SQLite compiled into the binary). No external SQLite dependency.

The DB file is NOT encrypted at the file level (no SQLCipher). Instead, only secret values are encrypted (field-level encryption). Metadata (project names, secret keys, tags) is stored in plaintext in the DB.

**Tradeoff acknowledged:** project names and secret key names are visible on disk without the master password. This is acceptable for v1 personal use. If this becomes a concern (team use, sensitive key names), we add SQLCipher in Phase 3.

### Migrations

Simple versioned migrations in `db.rs`. Each migration is a `&str` SQL string. Version tracked in `vault_meta` table under key `db_version`.

```rust
const MIGRATIONS: &[(&str, &str)] = &[
    ("001", include_str!("../migrations/001_initial.sql")),
    ("002", include_str!("../migrations/002_add_indexes.sql")),
];
```

### Connection Management

Single `Mutex<Connection>` in Tauri state. SQLite in WAL mode for better concurrent read performance (future: multiple readers when team sync is running).

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
```

---

## Tauri IPC Layer

### Session State

Managed as Tauri application state:

```rust
pub struct VaultState {
    pub key: Mutex<Option<Zeroizing<[u8; 32]>>>,
    pub db:  Mutex<Option<Connection>>,
}
```

- `key` is `None` when vault is locked
- Every command that requires access calls a helper that returns `AppError::VaultLocked` if `key` is None
- On `lock_vault`: key is zeroized via the `zeroize` crate before dropping

### Error Handling

```rust
#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Vault is locked")]
    VaultLocked,
    #[error("Wrong master password")]
    WrongPassword,
    #[error("Invalid recovery code")]
    WrongRecoveryCode,
    #[error("This vault has no recovery codes configured")]
    NoRecovery,
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

// Tauri commands return Result<T, String>
// Convert: AppError → String via Display
```

### Frontend Type Contracts

Types in `src/lib/types.ts` mirror Rust structs exactly:

```typescript
interface Project {
  id: string;
  name: string;
  description: string | null;
  created_at: number;
  updated_at: number;
}

interface Secret {
  id: string;
  project_id: string;
  key: string;
  value: string;        // decrypted, only present when explicitly fetched
  description: string | null;
  tags: string[];
  created_at: number;
  updated_at: number;
}

interface SecretMeta extends Omit<Secret, 'value'> {}
```

---

## Frontend Architecture

### State Management (Zustand)

```typescript
// store/vault.ts
interface VaultStore {
  isUnlocked: boolean;
  activeProjectId: string | null;
  projects: Project[];
  // actions
  unlock: (password: string) => Promise<void>;
  lock: () => Promise<void>;
  setActiveProject: (id: string) => void;
  refreshProjects: () => Promise<void>;
}
```

Secret values are never stored in global state. They are fetched on-demand per component and cleared on unmount.

### Navigation

Single-window app. React Router (hash-based):
- `/` → redirect to `/projects` or `/unlock`
- `/unlock` → UnlockScreen
- `/projects` → Home (project list)
- `/projects/:id` → Project (secret list for project)
- `/projects/:id/secrets/:secretId` → SecretDetail
- `/settings` → Settings

---

## Phase 3: Team Sync Architecture (Future)

### Overview

```
[User A local vault] ←→ [Sync Daemon] ←→ [Self-hosted API Server] ←→ [Sync Daemon] ←→ [User B local vault]
```

### Server responsibilities
- Store encrypted secret blobs (ciphertext only, never plaintext)
- Enforce project-level RBAC: `admin` | `reader`
- Provide a conflict-resolution log (last-write-wins per secret key, with version vector)
- Issue JWT tokens for authenticated users

### Key design constraint
The server never receives the vault key. It stores ciphertext. Even a compromised server reveals nothing without the vault key.

### Sharing mechanism
When an admin grants a user access to a project:
1. Admin re-encrypts the affected secrets with a **project key** (separate from vault key)
2. Project key is encrypted with each member's **public key** (asymmetric, generated on first login)
3. Members decrypt the project key with their private key → decrypt secrets

This is an envelope encryption model. Implementation detail for Phase 3.

### Schema additions for Phase 3

```sql
CREATE TABLE users (
  id         TEXT PRIMARY KEY,
  username   TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,   -- base64 X25519 public key
  created_at INTEGER NOT NULL
);

CREATE TABLE project_members (
  project_id      TEXT REFERENCES projects(id) ON DELETE CASCADE,
  user_id         TEXT REFERENCES users(id) ON DELETE CASCADE,
  role            TEXT NOT NULL CHECK(role IN ('admin', 'reader')),
  project_key_enc TEXT NOT NULL,  -- project key encrypted with user's public key
  PRIMARY KEY (project_id, user_id)
);

CREATE TABLE sync_log (
  id         TEXT PRIMARY KEY,
  table_name TEXT NOT NULL,
  row_id     TEXT NOT NULL,
  operation  TEXT NOT NULL CHECK(operation IN ('insert', 'update', 'delete')),
  synced_at  INTEGER,
  created_at INTEGER NOT NULL
);
```
