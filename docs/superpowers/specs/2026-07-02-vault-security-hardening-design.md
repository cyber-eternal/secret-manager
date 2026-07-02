# Vault Security Hardening — Design

**Date:** 2026-07-02
**Status:** Approved, pending implementation plan

Four security improvements to the vault, sequenced as one spec:

1. Password strength meter on create/change (zxcvbn, warn-but-allow)
2. Full-database encryption via SQLCipher (was: field-level on values only)
3. Failed-unlock rate limiting (exponential backoff, persisted)
4. Biometric unlock via macOS Touch ID + Keychain

---

## 1. Architecture change: encrypted DB + sidecar metadata file

### Problem

Today all unlock metadata (KDF params, password salt, master-key wrap, verify
blob, recovery-code wraps) lives in the `vault_meta` table **inside the DB**.
`vault_exists` and `vault_has_recovery` open the DB and read `vault_meta`
*before* the vault is unlocked.

SQLCipher encrypts the whole file, so no table — including `vault_meta` — is
readable until the DB is keyed with the master key. But the master key is only
available *after* reading the unlock metadata. Chicken-and-egg.

### Solution

Move all pre-unlock metadata **out** of the DB into a plaintext sidecar file.

**New invariant:** presence of the sidecar file ⇔ the vault is a v3 encrypted
vault. Absence of the sidecar (with a DB file present) ⇔ a legacy v1/v2
plaintext vault awaiting migration.

**Files on disk (next to each other):**

- `vault.db` — SQLCipher-encrypted database. Keyed by the 32-byte master key
  in raw-key mode: `PRAGMA key = "x'<64 hex chars>'"`. No double-KDF: the master
  key is already 32 random bytes, so SQLCipher uses it directly as the raw key
  (its own header salt handles HMAC subkey derivation). Encrypts **everything**:
  project names, secret keys, tag names, and secret values.
- `vault.meta.json` — plaintext sidecar. Schema:

  ```json
  {
    "format": "secret-manager-meta",
    "version": 3,
    "kdf": { "m_cost": 65536, "t_cost": 3, "p_cost": 4 },
    "pw_salt": "<hex>",
    "master_wrap": "<hex: AES-GCM(pw_key, master_key)>",
    "verify": "<hex: AES-GCM(master_key, VERIFY_PLAINTEXT)>",
    "recovery": [ { "salt": "<hex>", "wrap": "<hex>" }, ... ],
    "failed_attempts": 0,
    "locked_until_ms": 0,
    "biometric_wrap": null
  }
  ```

### Dependency

`rusqlite` feature changes from `bundled` to `bundled-sqlcipher-vendored-openssl`.
This vendors both SQLCipher and OpenSSL, keeping cross-platform builds
reproducible (no reliance on a system OpenSSL). Cost: heavier compile, requires
a C toolchain + perl for the OpenSSL build (present on macOS and standard CI
images).

### Code structure

- **New `sidecar.rs`** — owns the `Sidecar` struct plus `load(path)` and
  `save(path)`. All sidecar file I/O lives here.
- **`vault.rs`** — functions operate on `&mut Sidecar` + `&Connection`. They do
  **no** file I/O, so they remain unit-testable with an in-memory sidecar and an
  in-memory keyed DB. This is a rework of the current functions that read/write
  `vault_meta`.
- **`db.rs`** — add `open_keyed(path, key_hex)`: open → `PRAGMA key` (must be the
  first statement) → standard pragmas → migrations. The plaintext `open` is
  retained only for reading legacy DBs during migration.
- **Command layer** — pattern for mutating operations: load sidecar → call vault
  fn (mutates struct) → save sidecar. `db_version` stays in the DB (read after
  keying); only the pre-unlock fields move to the sidecar.

### Impact on existing commands

- `vault_exists` — checks sidecar file presence (or legacy DB presence); no DB
  open.
- `vault_has_recovery` — reads sidecar; no DB open.
- `create_vault` — generate master key → write sidecar → `open_keyed` new DB →
  run migrations.
- `unlock_vault` — read sidecar → derive password key → unwrap master key →
  `open_keyed` DB → confirm it opens (query `sqlite_master`).
- `recover_vault`, `regenerate_recovery_codes`, `change_master_password` —
  mutate the sidecar (not `vault_meta`) and persist it.
- `delete_vault` — also remove the sidecar file alongside `vault.db`,
  `-wal`, `-shm`.

Export/import are unaffected — they operate on already-unlocked plaintext data.

---

## 2. Migration: v1/v2 plaintext → v3 encrypted

Triggered on `unlock_vault` when **no sidecar exists** but a DB file does.

Steps:

1. Open the DB in plaintext.
2. Read `vault_meta`; run the existing v1/v2 unlock path to obtain the master
   key (proves the password is correct before touching anything).
3. Build a `Sidecar` from the meta rows (KDF params, salt, master wrap, verify,
   recovery entries).
4. Encrypt: `ATTACH DATABASE 'vault.db.new' AS enc KEY "x'<hex>'";
   SELECT sqlcipher_export('enc'); DETACH DATABASE enc;`
5. **Atomic swap with backup:** rename `vault.db` → `vault.db.bak`, rename
   `vault.db.new` → `vault.db`. The `.bak` (plaintext) is kept until the user
   clears it.
6. Open the new encrypted DB with the master key and confirm it opens (verifies
   the migration succeeded).
7. Write the sidecar file. Unlock proceeds normally.

**Backup handling:** `vault.db.bak` is retained after migration so a failed
migration never loses data. It is plaintext, so Settings gains a "Delete
migration backup" action (with a warning that the backup contains unencrypted
data). The app surfaces a one-time banner after migration prompting the user to
delete the backup once they've confirmed the vault opens.

Existing v1/v2 unlock tests remain meaningful — they exercise the legacy read
path that migration depends on.

---

## 3. Rate limiting (exponential backoff)

State lives in the sidecar (`failed_attempts`, `locked_until_ms`), so it
survives app restarts.

On `unlock_vault`:

- If `now_ms < locked_until_ms` → reject immediately with the remaining seconds.
  **Do not run Argon2.**
- On wrong password → `failed_attempts += 1`, compute `locked_until_ms` from the
  schedule, save the sidecar.
- On success → reset `failed_attempts = 0`, `locked_until_ms = 0`, save.

**Schedule** (attempt number → delay before next attempt):

| Attempt | Delay |
|--------:|-------|
| 1–3     | 0     |
| 4       | 5s    |
| 5       | 15s   |
| 6       | 30s   |
| 7       | 60s   |
| 8+      | 300s (cap) |

Never permanently locks out — the growing delay plus Argon2's per-attempt cost
makes brute force impractical without any data-loss risk. Applies to password
unlock only; recovery codes carry 120 bits of entropy, so brute force there is
already infeasible.

New error variant `AppError::RateLimited { retry_after_secs: u64 }`. The unlock
screen disables the button and shows a live countdown while locked.

---

## 4. Biometric unlock (macOS Touch ID)

Crate `security-framework`, gated with `#[cfg(target_os = "macos")]`. Other
platforms: the commands return `AppError::Unsupported` and the UI hides the
option.

**Enroll** (only from an unlocked vault):

1. Generate a random 32-byte token.
2. Store the token in the macOS Keychain with a `SecAccessControl` requiring
   biometric presence (`.biometryCurrentSet` + `.userPresence`).
3. Write `biometric_wrap = AES-GCM(token, master_key)` to the sidecar.

**Unlock via biometric:**

1. Fetch the token from the Keychain — the OS prompts for Touch ID.
2. Decrypt `biometric_wrap` with the token → master key.
3. `open_keyed` the DB.

**Disable:** delete the Keychain item and clear `biometric_wrap` in the sidecar.

Password unlock always works regardless of biometric state. A fingerprint-set
change or Keychain item removal invalidates biometric unlock (the wrap can no
longer be decrypted); the user falls back to the password. Storing only a random
token (not the master key) in the Keychain means the OS never holds the vault
key directly.

New commands: `biometric_available`, `biometric_enroll`, `biometric_unlock`,
`biometric_disable`. Settings gains a Touch ID toggle; the unlock screen shows a
"Unlock with Touch ID" button when enrolled.

---

## 5. Password strength meter (warn, don't block)

Frontend-only. Add `@zxcvbn-ts/core` and its common-language dictionary
packages. Show a strength bar (score 0–4) plus zxcvbn feedback on three screens:
create vault, change password, and the new-password field during recovery.

Score < 3 shows a warning and requires an explicit "use anyway" confirmation
(checkbox or second click); the password is **never** blocked — the user owns
their vault. No backend change.

---

## Implementation phases

One spec, sequenced plan. Phase 4 (password strength) is independent and lands
first as a quick, zero-risk win; the rest follow the dependency order.

1. **Password strength** — zxcvbn meter on create/change/recover. Frontend only.
2. **SQLCipher + sidecar refactor** (foundation) — new dependency, `sidecar.rs`,
   `db::open_keyed`, rework `vault.rs` + commands + tests, migration path with
   `.bak` backup.
3. **Rate limiting** — sidecar fields, unlock wrapper, `RateLimited` error, UI
   countdown.
4. **Biometric** — macOS Keychain integration, 4 commands, Settings toggle,
   unlock-screen button.

**Primary risk:** Phase 2 is the invasive one — a data migration plus a native
crypto dependency. Mitigations: the migration is atomic (write new DB, rename)
and retains the plaintext DB as `.bak` until the encrypted DB verifies-open, so
a failed migration cannot lose data.

## Non-goals

- Windows Hello / Linux biometric (macOS Touch ID only for now).
- Hard lockout (backoff never permanently locks the user out).
- Blocking weak passwords (warn only).
- Re-designing export/import (unaffected; already operates on decrypted data).
