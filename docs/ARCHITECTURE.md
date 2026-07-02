# Architecture

## Threat Model

What we protect against:
- **Disk theft / unauthorized file access** — the entire vault database is
  encrypted at rest (full-DB SQLCipher, v3), including project names, secret
  keys, tags, and values — not just secret values. Useless without the master
  password, a recovery code, or (on macOS) an enrolled biometric.
- **Memory scraping** — vault key zeroized on lock; secret values cleared from UI state on navigation
- **Weak passwords** — Argon2id with high cost parameters makes brute force expensive; a client-side strength meter (zxcvbn) warns on weak passwords at creation/change/recovery time (advisory only, never blocks)
- **Online guessing** — failed unlock attempts trigger an exponential backoff, persisted across restarts, so rapid password guessing against the unlock screen is throttled

What we do NOT protect against (out of scope for v1):
- Malware with root access on the user's machine
- Compromised Tauri/OS process memory
- Keyloggers capturing the master password
- The one-time `.bak` plaintext copy left behind after migrating a legacy
  pre-v3 vault (see "Legacy Migration" below) — it is plaintext by
  necessity until removed

---

## Encryption Layer

### Key Derivation

```
Input:  master_password (UTF-8 string)
        salt (32 random bytes, stored as pw_salt in vault.meta.json)

Algorithm: Argon2id
  m_cost:  65536  (64 MB memory)
  t_cost:  3      (iterations)
  p_cost:  4      (parallelism)
  hash_len: 32    (256-bit output)

Output: pw_key (32 bytes) — used only to unwrap the master key, held in
        memory ONLY, never persisted. The master key it unwraps is likewise
        memory-only (see "Envelope Encryption & Recovery" below).
```

Argon2id is preferred over Argon2i/Argon2d because it resists both side-channel and GPU attacks.

### Envelope Encryption & Recovery (vault format v3)

New vaults use envelope encryption combined with full-database encryption. A
random 32-byte **master key** both (a) keys SQLCipher for the entire SQLite
file and (b) is itself never stored in the clear — it is *wrapped*
(AES-256-GCM) by:

- a key derived from the **master password** (`master_wrap`)
- a key derived from each **recovery code** (the `recovery` list)
- optionally, a random **biometric token** stored in the macOS Keychain (see
  "Biometric Unlock (macOS Touch ID)" below)

```
master_key            = 32 random bytes (memory only)
pw_key                = Argon2id(password, pw_salt)
master_wrap           = AES-256-GCM(pw_key, master_key)
recovery[i].wrap      = AES-256-GCM(Argon2id(code_i, salt_i), master_key)
verify_blob           = AES-256-GCM(master_key, "secret-manager-verify-v1")
key_hex               = hex(master_key)              -- 64 hex chars
SQLCipher key         = PRAGMA key = "x'<key_hex>'"   -- keys the whole DB file
```

- **Unlock:** derive `pw_key` → decrypt `master_wrap` → master key → verify →
  open the SQLite file keyed with `key_hex`.
- **Recover:** for each recovery entry, derive its key from the entered code and
  try to decrypt its wrap; on success, re-wrap the master key under a new
  password. 8 single-use codes are generated at creation and shown once.
- **Change password / recover:** only the master-key wrap is rewritten — the
  database is **not** re-encrypted (the master key, and therefore the
  SQLCipher key, is stable).

Because the master key now keys the database directly, there is no separate
per-value encryption step to describe here — see "Full-Database Encryption
(SQLCipher)" below for what "encrypted" now covers.

**Legacy pre-v3 vaults** (plaintext SQLite, field-level value encryption only)
are migrated transparently on first unlock — see "Legacy Migration" below.

### Vault Verification

On first vault creation, store a verification blob (in the sidecar, see
below) so we can confirm the correct password on unlock without opening the
SQLCipher-encrypted database:

```
verify_plaintext = "secret-manager-verify-v1"
verify_nonce     = random 12 bytes
verify_blob      = AES-256-GCM(master_key, verify_plaintext, nonce=verify_nonce)
stored           = hex(verify_nonce || verify_blob)   -- sc.verify in vault.meta.json
```

On unlock: derive `pw_key` → decrypt `master_wrap` → candidate master key →
attempt to decrypt `verify_blob` with it → success means correct password
*before* we ever try to open the encrypted database file.

### Full-Database Encryption (SQLCipher)

The vault database (`vault.db`) is encrypted at the file level using
SQLCipher (via `rusqlite`'s `bundled-sqlcipher-vendored-openssl` feature),
keyed directly with the 32-byte master key rendered as 64 hex characters:

```
key_hex = hex(master_key)
PRAGMA key = "x'<key_hex>'"   -- must be the first statement on a fresh connection
```

This is "raw key" mode (no additional KDF inside SQLCipher — the master key
is already the output of Argon2id via the envelope above, so re-deriving
inside SQLCipher would be redundant). Everything in the schema is opaque
ciphertext without the key: project names, secret keys/descriptions, tags,
and secret values. Per-value `AES-256-GCM` encryption (nonce prepended to
ciphertext, as used by `crypto::encrypt`/`crypto::decrypt`) is still applied
to `secrets.value_encrypted` on top of the file-level encryption — defense in
depth, and it keeps the export/import and legacy-migration code paths (which
read/write individual secret values) unchanged. Opening the file with the
wrong key fails immediately on the first real query (SQLite reports
`SQLITE_NOTADB` / "file is not a database"); see
`db::tests::keyed_db_rejects_wrong_key`.

### Password Change

For a v3 vault, changing the password only re-derives `pw_key` from the new
password + a fresh `pw_salt` and rewrites `master_wrap` in the sidecar. The
master key — and therefore the SQLCipher key and every row in the database —
is untouched. Recovery wraps are left intact. The same holds for recovering
via a code: only `pw_salt`/`master_wrap` are rewritten.

**Legacy v1/v2 plaintext vaults**, once migrated to v3 (see "Legacy
Migration" below), behave identically going forward. Migration itself is the
only operation that touches the whole database — see below.

### The `vault.meta.json` Sidecar

Everything needed to derive/verify the master key **before** the SQLCipher
database can be opened lives in a plaintext JSON file next to the vault,
named `<vault_path>.meta.json` (e.g. `vault.db.meta.json`). This has to be
plaintext-readable pre-unlock — it's the chicken-and-egg piece that lets us
turn a password into the SQLCipher key in the first place. Structure
(`Sidecar` in `src-tauri/src/sidecar.rs`):

```jsonc
{
  "format": "secret-manager-meta",
  "version": 3,
  "kdf": { "m_cost": 65536, "t_cost": 3, "p_cost": 4 },
  "pw_salt": "…hex…",
  "master_wrap": "…hex, AES-256-GCM(pw_key, master_key)…",
  "verify": "…hex, AES-256-GCM(master_key, verify_plaintext)…",
  "recovery": [ { "salt": "…hex…", "wrap": "…hex…" }, /* 8 entries */ ],
  "failed_attempts": 0,
  "locked_until_ms": 0,
  "biometric_wrap": null
}
```

- Written atomically: serialized to `<sidecar>.tmp`, then renamed over the
  target (`Sidecar::save`), so a crash mid-write can't corrupt it.
- `failed_attempts` / `locked_until_ms` back the rate limiter (below);
  `biometric_wrap` backs Touch ID unlock (below). Both are absent/zeroed on a
  freshly created vault.
- Losing the sidecar without a copy of `pw_salt`/`master_wrap`/`recovery`
  makes the vault unrecoverable — back it up alongside `vault.db`.

### Legacy Migration (pre-v3 → v3)

Vaults created before this hardening pass stored everything (including
`vault_meta` with `pw_salt`, `master_wrap`, `verify_blob`, etc.) as plaintext
rows inside the SQLite file itself, and encrypted only `secrets.value_encrypted`.
`unlock_vault` detects this case (no `vault.meta.json` sidecar exists yet, but
the plaintext `vault.db` does) and migrates transparently, in `migrate.rs`:

1. Open the legacy plaintext DB and read its `vault_meta` rows.
2. **v2 legacy** (had `master_wrap`): derive `pw_key` from the entered
   password + stored `pw_salt`, decrypt `master_wrap` to recover the existing
   master key, verify it. The master key is preserved unchanged.
3. **v1 legacy** (no `master_wrap`, key derived directly from the password):
   derive the key and verify it; since secrets were field-encrypted directly
   under that derived key, it must become the v3 master key as-is (a fresh
   random key would orphan every encrypted value). A fresh `master_wrap` is
   built to wrap it under the current password so future unlocks use the v3
   path.
4. Wrong password at this step aborts before any file is touched — no
   partial migration.
5. Export the plaintext DB's contents into a new file via SQLCipher's
   `sqlcipher_export()`, keyed with the recovered/derived master key
   (`ATTACH DATABASE '<new>' AS enc KEY "x'<key_hex>'"; SELECT
   sqlcipher_export('enc');`).
6. Rename the original plaintext file to `<path>.bak` and the new encrypted
   file into place as `<path>`, then re-open it with the key and run a sanity
   query to confirm it's structurally sound before returning success.
7. Save the new `vault.meta.json` sidecar built from the recovered
   KDF/wrap/verify/recovery data.

The `.bak` file is a **one-time, plaintext** copy of the pre-migration
database — kept deliberately (never deleted automatically after a successful
migration) so an interrupted or buggy migration can't destroy data. It is
removed automatically only if the vault is later deleted entirely via
`delete_vault`. There is no dedicated Settings UI action to delete just the
`.bak` today; users who want it gone once they've confirmed the migrated
vault works correctly should remove the file manually.

### Unlock Rate Limiting

Failed unlock attempts are tracked in the sidecar (`failed_attempts`,
`locked_until_ms`) and gated by an exponential backoff schedule
(`vault::backoff_delay_ms`, enforced via `vault::check_rate_limit` /
`record_failure` / `record_success`):

| Consecutive failures | Backoff before next attempt |
|---|---|
| 0–3 | none |
| 4 | 5 s |
| 5 | 15 s |
| 6 | 30 s |
| 7 | 60 s |
| 8+ | 300 s (5 min), does not grow further |

`unlock_vault` checks the rate limit **before** running Argon2id (so a
blocked attempt doesn't even pay the KDF cost), and persists the updated
counters to the sidecar after every attempt. A blocked attempt returns
`AppError::RateLimited { retry_after_secs }`, which the UI surfaces as a
countdown on the unlock button. The backoff is intentionally capped and
always time-bounded — there is no failure count that permanently locks the
vault; a correct password (or valid recovery code, which is not
rate-limited by this counter) always works once the window elapses.

### Biometric Unlock (macOS Touch ID)

On macOS, once a vault is unlocked, a user can enroll biometric unlock
(`biometric.rs` + `vault::wrap_master_for_biometric`):

1. Generate a fresh random 32-byte token.
2. Store it in the macOS Keychain as a generic password, gated by a
   biometry-backed `SecAccessControl` (`BIOMETRY_CURRENT_SET | USER_PRESENCE`,
   `AccessibleWhenUnlockedThisDeviceOnly`) via `security-framework`.
   `BIOMETRY_CURRENT_SET` invalidates the Keychain item if the enrolled
   fingerprint/Face ID set changes, and `USER_PRESENCE` allows a passcode
   fallback if biometry is briefly unavailable.
3. Wrap the in-memory master key with that token (`AES-256-GCM(token,
   master_key)`) and store the wrap in the sidecar's `biometric_wrap` field.

Unlocking via Touch ID (`biometric_unlock`) fetches the token from the
Keychain — which triggers the OS Touch ID/Face ID prompt — then uses it to
unwrap and verify the master key exactly like a password unlock, and opens
the SQLCipher database with it. Disabling (`biometric_disable`) deletes the
Keychain item and clears `biometric_wrap` from the sidecar. Biometric unlock
is macOS-only; `biometric.rs` compiles to a no-op stub (`AppError::Unsupported`)
on other platforms, and `biometric_available` reports `false` there.

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
commands, as are the biometric commands (`biometric_enroll`/`biometric_unlock`/
`biometric_disable`), since they perform AES-256-GCM wrap/unwrap and a
Keychain round-trip that can block on the OS Touch ID/Face ID prompt. Tauri
runs sync commands on the webview's main thread; blocking there would freeze
rendering, button spinners, and loading state. Async commands run off the
main thread, keeping the UI responsive.

---

## Database Layer

### Engine

`rusqlite` with the `bundled-sqlcipher-vendored-openssl` feature: SQLite is
compiled into the binary together with SQLCipher and a vendored OpenSSL for
its crypto backend. No external SQLite/SQLCipher/OpenSSL dependency.

The DB file **is** encrypted at the file level (SQLCipher, raw-key mode keyed
directly with the 32-byte master key — see "Full-Database Encryption
(SQLCipher)" above). Project names, secret keys, descriptions, and tags are
no longer plaintext on disk; the entire file is opaque ciphertext without the
master key. `db::open` (unkeyed) is still used for reading legacy pre-v3
plaintext vaults during migration; all normal operation goes through
`db::open_keyed`.

This closes the tradeoff previously accepted for v1/v2: metadata (project
names, secret key names) is no longer visible on disk without the master
password.

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

Managed as Tauri application state, a single mutex around the whole session
(`src-tauri/src/state.rs`):

```rust
pub struct Session {
    pub db:   Option<Connection>,
    pub key:  Option<Zeroizing<[u8; KEY_LEN]>>,
    pub path: Option<PathBuf>,
}
pub struct VaultState(pub Mutex<Session>);
```

- `key`/`db` are `None` when the vault is locked; `is_unlocked()` requires both.
- Every command that requires access calls a helper (`db_and_key`/`db`) that
  returns `AppError::VaultLocked` if the relevant field is `None`.
- On `lock_vault`: `key` is set to `None`, which drops (and zeroizes, via
  `Zeroizing`) the in-memory master key. The `db` connection is left open.

### Error Handling

```rust
#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Vault is locked")]
    VaultLocked,
    #[error("Vault already exists")]
    VaultExists,
    #[error("No vault found at the given path")]
    VaultMissing,
    #[error("Wrong master password")]
    WrongPassword,
    #[error("Invalid recovery code")]
    WrongRecoveryCode,
    #[error("This vault has no recovery codes configured")]
    NoRecovery,
    #[error("Too many attempts. Try again in {retry_after_secs}s.")]
    RateLimited { retry_after_secs: u64 },
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Already exists: {0}")]
    AlreadyExists(String),
    #[error("Invalid input: {0}")]
    Invalid(String),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("IO error: {0}")]
    Io(String),
    #[error("This feature is not supported on this platform.")]
    Unsupported,
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
