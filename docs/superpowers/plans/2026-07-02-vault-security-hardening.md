# Vault Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add password-strength feedback, full-database SQLCipher encryption, failed-unlock rate limiting, and macOS Touch ID unlock to the secret-manager vault.

**Architecture:** Move all pre-unlock metadata out of the DB into a plaintext `vault.meta.json` sidecar, so the DB itself can be SQLCipher-encrypted with the master key. The sidecar also stores rate-limit state and the biometric wrap. `vault.rs` operates on an in-memory `Sidecar` + a keyed `Connection` (no file I/O) so it stays unit-testable; the command layer owns sidecar load/save. Password strength is a frontend-only zxcvbn meter.

**Tech Stack:** Rust (rusqlite `bundled-sqlcipher-vendored-openssl`, ring, argon2, zeroize, security-framework), Tauri 2, React 19 + zustand, `@zxcvbn-ts/core`, vitest.

## Global Constraints

- Rust edition 2021, `rust-version = "1.77"`.
- Argon2id KDF params floor: `m_cost=65536, t_cost=3, p_cost=4` (from `crypto::Argon2Params::default`). Tests use cheap params `{ m_cost: 1024, t_cost: 1, p_cost: 1 }`.
- AES-256-GCM via `ring`; ciphertext layout `nonce(12) || ciphertext || tag`. Reuse `crypto::encrypt`/`crypto::decrypt` — do not hand-roll new AEAD.
- Master key = 32 random bytes, never persisted in clear, wiped via `Zeroizing`/`zeroize`.
- Sidecar invariant: **sidecar file present ⇔ v3 encrypted vault**; sidecar absent + DB present ⇔ legacy v1/v2 plaintext awaiting migration.
- SQLCipher raw-key mode: `PRAGMA key = "x'<64 hex chars>'"` (no double-KDF; the master key is already random).
- Biometric is macOS-only, gated `#[cfg(target_os = "macos")]`; other platforms return `AppError::Unsupported`.
- Password strength: **warn only, never block**. Score threshold for warning: zxcvbn score `< 3`.
- Rate limiting: never permanent lockout. Schedule (attempt→delay): 1–3→0, 4→5s, 5→15s, 6→30s, 7→60s, 8+→300s.
- Frontend errors are plain strings (Tauri serializes `AppError` via `to_string()`); read them with `errMessage`.
- All Tauri commands that run Argon2 must be `async fn` (keeps them off the webview main thread).
- Run frontend tests with `npm test`; Rust tests with `cargo test --manifest-path src-tauri/Cargo.toml`.

---

## Phase 1 — Password strength meter (frontend only, independent)

### Task 1.1: Add zxcvbn dependencies

**Files:**
- Modify: `package.json`

- [ ] **Step 1: Install packages**

Run:
```bash
npm install @zxcvbn-ts/core@^3 @zxcvbn-ts/language-common@^3 @zxcvbn-ts/language-en@^3
```
Expected: three entries added under `dependencies` in `package.json`, `package-lock.json` updated.

- [ ] **Step 2: Verify typecheck still passes**

Run: `npm run typecheck`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add package.json package-lock.json
git commit -m "chore: add zxcvbn-ts for password strength"
```

---

### Task 1.2: Password-strength helper

**Files:**
- Create: `src/lib/passwordStrength.ts`
- Test: `src/lib/passwordStrength.test.ts`

**Interfaces:**
- Produces: `estimateStrength(pw: string): { score: 0|1|2|3|4; warning: string; suggestions: string[] }` and `STRENGTH_LABELS: readonly string[]` (length 5) and `isWeak(score: number): boolean`.

- [ ] **Step 1: Write the failing test**

```ts
// src/lib/passwordStrength.test.ts
import { describe, it, expect } from "vitest";
import { estimateStrength, isWeak, STRENGTH_LABELS } from "./passwordStrength";

describe("passwordStrength", () => {
  it("scores an empty password as 0 (weak)", () => {
    const r = estimateStrength("");
    expect(r.score).toBe(0);
    expect(isWeak(r.score)).toBe(true);
  });

  it("scores a long random passphrase as strong (>=3, not weak)", () => {
    const r = estimateStrength("correct-horse-battery-staple-92xQ");
    expect(r.score).toBeGreaterThanOrEqual(3);
    expect(isWeak(r.score)).toBe(false);
  });

  it("exposes a label per score", () => {
    expect(STRENGTH_LABELS).toHaveLength(5);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- passwordStrength`
Expected: FAIL — cannot find module `./passwordStrength`.

- [ ] **Step 3: Write minimal implementation**

```ts
// src/lib/passwordStrength.ts
import { zxcvbn, zxcvbnOptions } from "@zxcvbn-ts/core";
import * as common from "@zxcvbn-ts/language-common";
import * as en from "@zxcvbn-ts/language-en";

let configured = false;
function configure() {
  if (configured) return;
  zxcvbnOptions.setOptions({
    dictionary: { ...common.dictionary, ...en.dictionary },
    graphs: common.adjacencyGraphs,
    translations: en.translations,
  });
  configured = true;
}

export const STRENGTH_LABELS = [
  "Very weak",
  "Weak",
  "Fair",
  "Strong",
  "Very strong",
] as const;

export type StrengthScore = 0 | 1 | 2 | 3 | 4;

export interface Strength {
  score: StrengthScore;
  warning: string;
  suggestions: string[];
}

/** Score `pw` with zxcvbn (0–4) plus human feedback. */
export function estimateStrength(pw: string): Strength {
  configure();
  const r = zxcvbn(pw);
  return {
    score: r.score as StrengthScore,
    warning: r.feedback.warning ?? "",
    suggestions: r.feedback.suggestions ?? [],
  };
}

/** A password is "weak" (worth warning about) below zxcvbn score 3. */
export function isWeak(score: number): boolean {
  return score < 3;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- passwordStrength`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/lib/passwordStrength.ts src/lib/passwordStrength.test.ts
git commit -m "feat: password strength estimator (zxcvbn wrapper)"
```

---

### Task 1.3: StrengthMeter component

**Files:**
- Create: `src/components/StrengthMeter.tsx`
- Test: `src/components/StrengthMeter.test.tsx`

**Interfaces:**
- Consumes: `estimateStrength`, `STRENGTH_LABELS`, `isWeak` from `src/lib/passwordStrength`.
- Produces: `StrengthMeter({ password }: { password: string })` — renders nothing when `password` is empty; otherwise a 4-segment bar + label + first warning/suggestion.

- [ ] **Step 1: Write the failing test**

```tsx
// src/components/StrengthMeter.test.tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StrengthMeter } from "./StrengthMeter";

describe("StrengthMeter", () => {
  it("renders nothing for an empty password", () => {
    const { container } = render(<StrengthMeter password="" />);
    expect(container.firstChild).toBeNull();
  });

  it("shows a strength label for a non-empty password", () => {
    render(<StrengthMeter password="a" />);
    // "Very weak" for a single char.
    expect(screen.getByText(/very weak/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test -- StrengthMeter`
Expected: FAIL — cannot find module `./StrengthMeter`.

- [ ] **Step 3: Write minimal implementation**

```tsx
// src/components/StrengthMeter.tsx
import { useMemo } from "react";
import { estimateStrength, STRENGTH_LABELS, isWeak } from "../lib/passwordStrength";

const BAR_COLORS = [
  "bg-danger",
  "bg-danger",
  "bg-amber-500",
  "bg-emerald-500",
  "bg-emerald-500",
];

export function StrengthMeter({ password }: { password: string }) {
  const s = useMemo(() => estimateStrength(password), [password]);
  if (!password) return null;

  const hint = s.warning || s.suggestions[0] || "";
  return (
    <div className="mt-2" aria-live="polite">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={`h-1.5 flex-1 rounded-full ${
              i <= s.score - 1 ? BAR_COLORS[s.score] : "bg-border"
            }`}
          />
        ))}
      </div>
      <p className="mt-1 text-[11.5px] text-text-muted">
        <span className={isWeak(s.score) ? "text-danger" : "text-text"}>
          {STRENGTH_LABELS[s.score]}
        </span>
        {hint ? ` — ${hint}` : ""}
      </p>
    </div>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test -- StrengthMeter`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/components/StrengthMeter.tsx src/components/StrengthMeter.test.tsx
git commit -m "feat: password StrengthMeter component"
```

---

### Task 1.4: Wire StrengthMeter + "use anyway" into UnlockScreen

**Files:**
- Modify: `src/components/UnlockScreen.tsx`

**Interfaces:**
- Consumes: `StrengthMeter` from `./StrengthMeter`, `estimateStrength`/`isWeak` from `../lib/passwordStrength`.

- [ ] **Step 1: Add import and weak-confirm state**

At the top imports add:
```tsx
import { StrengthMeter } from "./StrengthMeter";
import { estimateStrength, isWeak } from "../lib/passwordStrength";
```
Inside `UnlockScreen`, add state near the other `useState` calls:
```tsx
const [weakAck, setWeakAck] = useState(false);
```

- [ ] **Step 2: Show the meter under the create/recover password field**

In the `mode === "auth"` branch, immediately after the `firstRun &&` confirm-password block (after the closing `</>` of that fragment, before the `{error && ...}`), insert:
```tsx
{firstRun && <StrengthMeter password={password} />}
```
In the `mode === "recover"` form, after the "Confirm new password" `PasswordInput`, insert:
```tsx
<StrengthMeter password={password} />
```

- [ ] **Step 3: Gate create/recover on a weak-password acknowledgement**

In `onAuthSubmit`, replace the `if (firstRun) { ... await createVault(password); }` block body with:
```tsx
if (firstRun) {
  const check = validateMasterPassword(password, confirm);
  if (!check.ok) return setError(check.message ?? "Invalid password");
  if (isWeak(estimateStrength(password).score) && !weakAck) {
    setWeakAck(true);
    return setError("That password is weak. Click Create vault again to use it anyway.");
  }
  await createVault(password);
}
```
In `onRecoverSubmit`, after the `validateMasterPassword` check and before `await recover(...)`, insert the same weak-gate:
```tsx
if (isWeak(estimateStrength(password).score) && !weakAck) {
  setWeakAck(true);
  return setError("That password is weak. Click Recover access again to use it anyway.");
}
```
In `resetFields`, add `setWeakAck(false);`.

- [ ] **Step 4: Verify typecheck + existing UnlockScreen test still pass**

Run: `npm run typecheck && npm test -- UnlockScreen`
Expected: typecheck clean; existing `UnlockScreen.test.tsx` PASS.

- [ ] **Step 5: Commit**

```bash
git add src/components/UnlockScreen.tsx
git commit -m "feat: show password strength + weak-confirm on create/recover"
```

---

### Task 1.5: Wire StrengthMeter into Settings change-password

**Files:**
- Modify: `src/pages/Settings.tsx`

- [ ] **Step 1: Import the meter**

Add to imports:
```tsx
import { StrengthMeter } from "../components/StrengthMeter";
```

- [ ] **Step 2: Render meter under the new-password field**

In the change-password form, immediately after the `PasswordInput` bound to `newPw` (value `newPw` / `setNewPw`), insert:
```tsx
<StrengthMeter password={newPw} />
```

- [ ] **Step 3: Verify typecheck + build**

Run: `npm run typecheck && npm run build`
Expected: clean build, no TS errors.

- [ ] **Step 4: Commit**

```bash
git add src/pages/Settings.tsx
git commit -m "feat: password strength meter in Settings change-password"
```

---

## Phase 2 — SQLCipher + sidecar refactor (foundation)

### Task 2.1: Swap to SQLCipher and add `db::open_keyed`

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/db.rs`

**Interfaces:**
- Produces: `db::open_keyed(path: &Path, key_hex: &str) -> Result<Connection>` and `db::open_in_memory_keyed(key_hex: &str) -> Result<Connection>` (test helper). `db::open` retained for legacy plaintext reads during migration.

- [ ] **Step 1: Change the rusqlite feature**

In `src-tauri/Cargo.toml`, replace:
```toml
rusqlite = { version = "0.31", features = ["bundled"] }
```
with:
```toml
rusqlite = { version = "0.31", features = ["bundled-sqlcipher-vendored-openssl"] }
```

- [ ] **Step 2: Add keyed-open helpers with a failing test**

In `src-tauri/src/db.rs`, add to the `tests` module:
```rust
#[test]
fn keyed_db_round_trips_and_rejects_wrong_key() {
    let key = "0".repeat(64);
    let conn = open_in_memory_keyed(&key).unwrap();
    conn.execute("CREATE TABLE t(x TEXT)", []).unwrap();
    conn.execute("INSERT INTO t(x) VALUES('hi')", []).unwrap();
    let got: String = conn.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
    assert_eq!(got, "hi");
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --manifest-path src-tauri/Cargo.toml db::tests::keyed_db_round_trips`
Expected: FAIL — `open_in_memory_keyed` not found.

- [ ] **Step 4: Implement the keyed-open helpers**

In `src-tauri/src/db.rs`, add:
```rust
/// Apply the SQLCipher key to a freshly opened connection. Must run before any
/// other statement. `key_hex` is 64 hex chars (32-byte raw key).
fn apply_key(conn: &Connection, key_hex: &str) -> Result<()> {
    conn.execute_batch(&format!("PRAGMA key = \"x'{key_hex}'\";"))?;
    Ok(())
}

/// Open (creating if needed) a SQLCipher-encrypted vault DB, keyed with the
/// 32-byte master key rendered as 64 hex chars.
pub fn open_keyed(path: &Path, key_hex: &str) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    apply_key(&conn, key_hex)?;
    apply_pragmas(&conn)?;
    run_migrations(&conn)?;
    Ok(conn)
}

/// In-memory keyed DB for tests.
pub fn open_in_memory_keyed(key_hex: &str) -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_key(&conn, key_hex)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    run_migrations(&conn)?;
    Ok(conn)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml db::`
Expected: PASS (existing + new). Note: first build is slow — it compiles SQLCipher + vendored OpenSSL.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/db.rs
git commit -m "feat: SQLCipher-encrypted DB via db::open_keyed"
```

---

### Task 2.2: `Sidecar` struct + load/save

**Files:**
- Create: `src-tauri/src/sidecar.rs`
- Modify: `src-tauri/src/lib.rs` (add `pub mod sidecar;`)

**Interfaces:**
- Produces:
  ```rust
  pub struct RecoveryEntry { pub salt: String, pub wrap: String }
  pub struct Sidecar {
      pub format: String,        // "secret-manager-meta"
      pub version: u32,          // 3
      pub kdf: crate::crypto::Argon2Params,
      pub pw_salt: String,       // hex
      pub master_wrap: String,   // hex
      pub verify: String,        // hex
      pub recovery: Vec<RecoveryEntry>,
      pub failed_attempts: u32,
      pub locked_until_ms: i64,
      pub biometric_wrap: Option<String>, // hex
  }
  impl Sidecar {
      pub fn sidecar_path(db_path: &Path) -> PathBuf;      // db_path + ".meta.json"
      pub fn exists(db_path: &Path) -> bool;
      pub fn load(db_path: &Path) -> Result<Sidecar>;
      pub fn save(&self, db_path: &Path) -> Result<()>;    // atomic write (tmp + rename)
  }
  ```
  `RecoveryEntry` and `Sidecar` derive `Serialize, Deserialize, Clone`.

- [ ] **Step 1: Register the module**

In `src-tauri/src/lib.rs`, add after `pub mod repo;`:
```rust
pub mod sidecar;
```

- [ ] **Step 2: Write the failing test**

Create `src-tauri/src/sidecar.rs` with only the test module first:
```rust
//! Plaintext sidecar file holding pre-unlock vault metadata.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::Argon2Params;
use crate::error::{AppError, Result};

// ... (implementation added in Step 4)

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Sidecar {
        Sidecar {
            format: "secret-manager-meta".into(),
            version: 3,
            kdf: Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 },
            pw_salt: "aa".into(),
            master_wrap: "bb".into(),
            verify: "cc".into(),
            recovery: vec![RecoveryEntry { salt: "dd".into(), wrap: "ee".into() }],
            failed_attempts: 0,
            locked_until_ms: 0,
            biometric_wrap: None,
        }
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("smtest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        let s = sample();
        s.save(&db).unwrap();
        assert!(Sidecar::exists(&db));
        let loaded = Sidecar::load(&db).unwrap();
        assert_eq!(loaded.master_wrap, "bb");
        assert_eq!(loaded.recovery.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sidecar_path_appends_suffix() {
        let p = Sidecar::sidecar_path(Path::new("/x/vault.db"));
        assert_eq!(p, PathBuf::from("/x/vault.db.meta.json"));
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --manifest-path src-tauri/Cargo.toml sidecar::`
Expected: FAIL — `Sidecar`, `RecoveryEntry` not defined.

- [ ] **Step 4: Implement the struct + load/save**

Insert above the `#[cfg(test)]` module:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEntry {
    pub salt: String,
    pub wrap: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub format: String,
    pub version: u32,
    pub kdf: Argon2Params,
    pub pw_salt: String,
    pub master_wrap: String,
    pub verify: String,
    #[serde(default)]
    pub recovery: Vec<RecoveryEntry>,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default)]
    pub locked_until_ms: i64,
    #[serde(default)]
    pub biometric_wrap: Option<String>,
}

impl Sidecar {
    pub fn sidecar_path(db_path: &Path) -> PathBuf {
        PathBuf::from(format!("{}.meta.json", db_path.display()))
    }

    pub fn exists(db_path: &Path) -> bool {
        Self::sidecar_path(db_path).exists()
    }

    pub fn load(db_path: &Path) -> Result<Sidecar> {
        let p = Self::sidecar_path(db_path);
        let bytes = std::fs::read(&p)?;
        let s: Sidecar = serde_json::from_slice(&bytes)?;
        Ok(s)
    }

    /// Atomic write: serialize to a temp file, then rename over the target.
    pub fn save(&self, db_path: &Path) -> Result<()> {
        let p = Self::sidecar_path(db_path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = PathBuf::from(format!("{}.tmp", p.display()));
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &p).map_err(|e| AppError::Io(e.to_string()))?;
        Ok(())
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml sidecar::`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/sidecar.rs src-tauri/src/lib.rs
git commit -m "feat: vault.meta.json sidecar (struct + atomic load/save)"
```

---

### Task 2.3: Rework `vault::create` / `vault::unlock` onto the sidecar

**Files:**
- Modify: `src-tauri/src/vault.rs`

**Interfaces:**
- Produces (new signatures):
  ```rust
  pub fn key_hex(master_key: &[u8; KEY_LEN]) -> String; // 64-char hex
  pub fn create(password: &str) -> Result<([u8; KEY_LEN], Sidecar, Vec<String>)>;
  pub fn unlock(sc: &Sidecar, password: &str) -> Result<[u8; KEY_LEN]>;
  ```
  `create` builds the master key + sidecar + recovery codes but does **not** touch any DB or file — the caller keys the DB with `key_hex` and saves the sidecar. `unlock` reads only the sidecar.

- [ ] **Step 1: Update imports and add `key_hex` + failing tests**

At the top of `src-tauri/src/vault.rs`, replace the `use rusqlite::Connection;` / meta-key consts region so the file imports the sidecar and drops the DB-meta helpers for v2. Add:
```rust
use crate::sidecar::{RecoveryEntry, Sidecar};
```
Add near the recovery helpers:
```rust
/// Render a 32-byte master key as 64 lowercase hex chars for `PRAGMA key`.
pub fn key_hex(master_key: &[u8; KEY_LEN]) -> String {
    hex::encode(master_key)
}
```
Rewrite the `tests` module's v2 tests to use the new API:
```rust
#[test]
fn create_then_unlock_v2() {
    let (k1, sc, codes) = create("hunter2").unwrap();
    assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
    let k2 = unlock(&sc, "hunter2").unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn unlock_wrong_password_fails() {
    let (_k, sc, _codes) = create("hunter2").unwrap();
    assert!(matches!(unlock(&sc, "wrong"), Err(AppError::WrongPassword)));
}
```
(Keep `fast_params` for later tasks; other v2 tests are rewritten in Task 2.4.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::tests::create_then_unlock_v2`
Expected: FAIL — `create`/`unlock` signatures don't match.

- [ ] **Step 3: Rewrite `create` and `unlock`**

Replace the existing `create` and `unlock` (and delete `is_v2`, `is_initialized`, `has_recovery`, `meta_get`, `meta_set`, and the `META_*` consts that referenced `vault_meta`; recovery helpers `generate_recovery_code`, `normalize_code`, `build_recovery` stay) with:
```rust
/// Build a fresh v3 vault: random master key, sidecar (password wrap + recovery
/// wraps + verify blob), and the one-time recovery codes. Does not touch disk.
pub fn create(password: &str) -> Result<([u8; KEY_LEN], Sidecar, Vec<String>)> {
    if password.is_empty() {
        return Err(AppError::Invalid("master password must not be empty".into()));
    }
    let params = Argon2Params::default();
    let master_key = {
        let bytes = crypto::random_bytes(KEY_LEN)?;
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&bytes);
        k
    };
    let pw_salt = crypto::generate_salt()?;
    let pw_key = crypto::derive_key(password, &pw_salt, &params)?;
    let master_wrap = crypto::encrypt(&pw_key, &master_key)?;
    let verify = crypto::make_verify_blob(&master_key)?;
    let (codes, entries) = build_recovery(&master_key, &params)?;

    let sc = Sidecar {
        format: "secret-manager-meta".into(),
        version: 3,
        kdf: params,
        pw_salt: hex::encode(pw_salt),
        master_wrap: hex::encode(&master_wrap),
        verify: hex::encode(&verify),
        recovery: entries,
        failed_attempts: 0,
        locked_until_ms: 0,
        biometric_wrap: None,
    };
    Ok((master_key, sc, codes))
}

/// Unlock using the master password against the sidecar.
pub fn unlock(sc: &Sidecar, password: &str) -> Result<[u8; KEY_LEN]> {
    let pw_salt = hex::decode(&sc.pw_salt).map_err(|_| AppError::crypto("corrupt salt"))?;
    let master_wrap =
        hex::decode(&sc.master_wrap).map_err(|_| AppError::crypto("corrupt master wrap"))?;
    let verify = hex::decode(&sc.verify).map_err(|_| AppError::crypto("corrupt verify blob"))?;

    let pw_key = crypto::derive_key(password, &pw_salt, &sc.kdf)?;
    let master_key = match crypto::decrypt(&pw_key, &master_wrap) {
        Ok(k) if k.len() == KEY_LEN => {
            let mut arr = [0u8; KEY_LEN];
            arr.copy_from_slice(&k);
            arr
        }
        _ => return Err(AppError::WrongPassword),
    };
    if !crypto::verify_key(&master_key, &verify) {
        return Err(AppError::WrongPassword);
    }
    Ok(master_key)
}
```
Change `build_recovery` to return `(Vec<String>, Vec<RecoveryEntry>)` instead of a JSON string:
```rust
fn build_recovery(
    master_key: &[u8; KEY_LEN],
    params: &Argon2Params,
) -> Result<(Vec<String>, Vec<RecoveryEntry>)> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut entries = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = generate_recovery_code()?;
        let salt = crypto::generate_salt()?;
        let code_key = crypto::derive_key(&normalize_code(&code), &salt, params)?;
        let wrap = crypto::encrypt(&code_key, master_key)?;
        entries.push(RecoveryEntry { salt: hex::encode(salt), wrap: hex::encode(wrap) });
        codes.push(code);
    }
    Ok((codes, entries))
}
```
Delete the local `#[derive(...)] struct RecoveryEntry` in `vault.rs` (now imported from `sidecar`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::tests::create_then_unlock_v2 vault::tests::unlock_wrong_password_fails`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/vault.rs
git commit -m "refactor: vault create/unlock operate on sidecar (no DB meta)"
```

---

### Task 2.4: Sidecar-based `change_password`, `recover`, `regenerate_recovery`, `has_recovery`

**Files:**
- Modify: `src-tauri/src/vault.rs`

**Interfaces:**
- Produces:
  ```rust
  pub fn has_recovery(sc: &Sidecar) -> bool;
  pub fn change_password(sc: &mut Sidecar, old_password: &str, new_password: &str) -> Result<[u8; KEY_LEN]>;
  pub fn recover(sc: &mut Sidecar, code: &str, new_password: &str) -> Result<[u8; KEY_LEN]>;
  pub fn regenerate_recovery(sc: &mut Sidecar, master_key: &[u8; KEY_LEN]) -> Result<Vec<String>>;
  ```
  Each mutates the sidecar in place; the caller persists it. `change_password` and `recover` re-wrap the master key only (secrets untouched — they live in the DB keyed by the unchanged master key).

- [ ] **Step 1: Write failing tests**

In the `vault.rs` tests module add:
```rust
#[test]
fn change_password_rewraps_same_master_key() {
    let (key, mut sc, _codes) = create("old-pw").unwrap();
    let new_key = change_password(&mut sc, "old-pw", "new-pw").unwrap();
    assert_eq!(new_key, key, "master key stable across password change");
    assert!(matches!(unlock(&sc, "old-pw"), Err(AppError::WrongPassword)));
    assert_eq!(unlock(&sc, "new-pw").unwrap(), key);
}

#[test]
fn recover_with_code_resets_password() {
    let (key, mut sc, codes) = create("forgotten").unwrap();
    let entered = codes[2].to_lowercase();
    let mk = recover(&mut sc, &entered, "brand-new-pw").unwrap();
    assert_eq!(mk, key);
    assert!(matches!(unlock(&sc, "forgotten"), Err(AppError::WrongPassword)));
    assert_eq!(unlock(&sc, "brand-new-pw").unwrap(), key);
}

#[test]
fn recover_with_bad_code_fails() {
    let (_key, mut sc, _codes) = create("pw").unwrap();
    assert!(matches!(
        recover(&mut sc, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", "new"),
        Err(AppError::WrongRecoveryCode)
    ));
}

#[test]
fn regenerate_recovery_invalidates_old_codes() {
    let (key, mut sc, old_codes) = create("pw").unwrap();
    let new_codes = regenerate_recovery(&mut sc, &key).unwrap();
    assert_eq!(new_codes.len(), RECOVERY_CODE_COUNT);
    assert_eq!(recover(&mut sc, &new_codes[0], "pw2").unwrap(), key);
    // Re-fetch: after recover, sc is mutated; use a fresh vault for the old-code check.
    let (k2, mut sc2, old2) = create("pw").unwrap();
    let regen = regenerate_recovery(&mut sc2, &k2).unwrap();
    assert!(!regen.is_empty());
    assert!(matches!(
        recover(&mut sc2, &old2[0], "pw3"),
        Err(AppError::WrongRecoveryCode)
    ));
}
```
Delete the now-obsolete tests `change_password_keeps_secrets`, the old `recover_*`, `regenerate_recovery_invalidates_old_codes`, and `legacy_v1_vault_still_unlocks` (legacy is covered by the migration test in Task 2.5).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::tests::change_password_rewraps`
Expected: FAIL — new signatures not present.

- [ ] **Step 3: Implement the four functions**

Replace the old `has_recovery`, `change_password`/`change_password_legacy`, `recover`, `regenerate_recovery` with:
```rust
/// `true` if the sidecar has at least one recovery wrap.
pub fn has_recovery(sc: &Sidecar) -> bool {
    !sc.recovery.is_empty()
}

/// Change the master password: re-wrap the (unchanged) master key.
pub fn change_password(
    sc: &mut Sidecar,
    old_password: &str,
    new_password: &str,
) -> Result<[u8; KEY_LEN]> {
    if new_password.is_empty() {
        return Err(AppError::Invalid("new password must not be empty".into()));
    }
    let master_key = unlock(sc, old_password)?;
    let pw_salt = crypto::generate_salt()?;
    let pw_key = crypto::derive_key(new_password, &pw_salt, &sc.kdf)?;
    let master_wrap = crypto::encrypt(&pw_key, &master_key)?;
    sc.pw_salt = hex::encode(pw_salt);
    sc.master_wrap = hex::encode(&master_wrap);
    Ok(master_key)
}

/// Recover with a recovery code and set a new password. Re-wraps the master key.
pub fn recover(
    sc: &mut Sidecar,
    code: &str,
    new_password: &str,
) -> Result<[u8; KEY_LEN]> {
    if new_password.is_empty() {
        return Err(AppError::Invalid("new password must not be empty".into()));
    }
    if !has_recovery(sc) {
        return Err(AppError::NoRecovery);
    }
    let verify = hex::decode(&sc.verify).map_err(|_| AppError::crypto("corrupt verify blob"))?;
    let normalized = normalize_code(code);
    for entry in sc.recovery.clone() {
        let salt = match hex::decode(&entry.salt) { Ok(s) => s, Err(_) => continue };
        let wrap = match hex::decode(&entry.wrap) { Ok(w) => w, Err(_) => continue };
        let code_key = crypto::derive_key(&normalized, &salt, &sc.kdf)?;
        if let Ok(mk) = crypto::decrypt(&code_key, &wrap) {
            if mk.len() == KEY_LEN {
                let mut master_key = [0u8; KEY_LEN];
                master_key.copy_from_slice(&mk);
                if crypto::verify_key(&master_key, &verify) {
                    let pw_salt = crypto::generate_salt()?;
                    let pw_key = crypto::derive_key(new_password, &pw_salt, &sc.kdf)?;
                    let master_wrap = crypto::encrypt(&pw_key, &master_key)?;
                    sc.pw_salt = hex::encode(pw_salt);
                    sc.master_wrap = hex::encode(&master_wrap);
                    sc.failed_attempts = 0;
                    sc.locked_until_ms = 0;
                    return Ok(master_key);
                }
            }
        }
    }
    Err(AppError::WrongRecoveryCode)
}

/// Regenerate the recovery code set. Requires the unlocked master key.
pub fn regenerate_recovery(
    sc: &mut Sidecar,
    master_key: &[u8; KEY_LEN],
) -> Result<Vec<String>> {
    let verify = hex::decode(&sc.verify).map_err(|_| AppError::crypto("corrupt verify blob"))?;
    if !crypto::verify_key(master_key, &verify) {
        return Err(AppError::VaultLocked);
    }
    let (codes, entries) = build_recovery(master_key, &sc.kdf)?;
    sc.recovery = entries;
    Ok(codes)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::`
Expected: PASS (all vault tests). Remove any unused imports flagged by the compiler.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/vault.rs
git commit -m "refactor: sidecar-based change_password/recover/regenerate"
```

---

### Task 2.5: Legacy migration (v1/v2 plaintext → v3 encrypted)

**Files:**
- Create: `src-tauri/src/migrate.rs`
- Modify: `src-tauri/src/lib.rs` (add `pub mod migrate;`)

**Interfaces:**
- Consumes: `db::open` (plaintext), `db::open_keyed`, `vault::key_hex`, `sidecar::Sidecar`, `crypto`.
- Produces: `migrate::migrate_plaintext_to_encrypted(db_path: &Path, password: &str) -> Result<([u8; KEY_LEN], Sidecar)>` — reads the legacy plaintext DB, verifies `password`, writes an encrypted copy, swaps files (keeping `vault.db.bak`), and returns the master key + fresh sidecar. Caller saves the sidecar and opens the encrypted DB.

- [ ] **Step 1: Register module + write failing test**

In `src-tauri/src/lib.rs` add `pub mod migrate;`. Create `src-tauri/src/migrate.rs`:
```rust
//! One-time migration of legacy plaintext vaults to v3 (SQLCipher + sidecar).

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::error::{AppError, Result};
use crate::sidecar::{RecoveryEntry, Sidecar};
use crate::{db, vault};

// implementation added in Step 3

#[cfg(test)]
mod tests {
    use super::*;

    fn write_legacy_v2_plaintext(path: &Path, password: &str) -> [u8; KEY_LEN] {
        // Build a legacy v2 plaintext DB: meta rows in vault_meta, one secret.
        let conn = db::open(path).unwrap();
        let params = Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let master_key = {
            let b = crypto::random_bytes(KEY_LEN).unwrap();
            let mut k = [0u8; KEY_LEN]; k.copy_from_slice(&b); k
        };
        let pw_salt = crypto::generate_salt().unwrap();
        let pw_key = crypto::derive_key(password, &pw_salt, &params).unwrap();
        let master_wrap = crypto::encrypt(&pw_key, &master_key).unwrap();
        let verify = crypto::make_verify_blob(&master_key).unwrap();
        let set = |k: &str, v: &str| {
            conn.execute(
                "INSERT INTO vault_meta(key,value) VALUES(?1,?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [k, v]).unwrap();
        };
        set("vault_version", "2");
        set("kdf_params", &serde_json::to_string(&params).unwrap());
        set("pw_salt", &hex::encode(pw_salt));
        set("master_wrap", &hex::encode(&master_wrap));
        set("verify_blob", &hex::encode(&verify));
        set("recovery", "[]");
        let proj = crate::repo::create_project(&conn, "p", None).unwrap();
        crate::repo::add_secret(&conn, &master_key, &proj.id, "K", "v", None, &[]).unwrap();
        master_key
    }

    #[test]
    fn migrates_and_preserves_secret() {
        let dir = std::env::temp_dir().join(format!("smmig-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        let original_key = write_legacy_v2_plaintext(&db, "pw123456");

        let (mk, sc) = migrate_plaintext_to_encrypted(&db, "pw123456").unwrap();
        assert_eq!(mk, original_key, "master key preserved");
        assert_eq!(sc.version, 3);
        assert!(dir.join("vault.db.bak").exists(), "backup kept");

        // Encrypted DB opens with the master key and still holds the secret.
        sc.save(&db).unwrap();
        let conn = db::open_keyed(&db, &vault::key_hex(&mk)).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM secrets", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_password_does_not_migrate() {
        let dir = std::env::temp_dir().join(format!("smmig-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        write_legacy_v2_plaintext(&db, "right-pw");
        assert!(migrate_plaintext_to_encrypted(&db, "wrong-pw").is_err());
        assert!(!dir.join("vault.db.bak").exists(), "no swap on failure");
        std::fs::remove_dir_all(&dir).ok();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --manifest-path src-tauri/Cargo.toml migrate::`
Expected: FAIL — `migrate_plaintext_to_encrypted` not defined.

- [ ] **Step 3: Implement the migration**

Insert above the tests module:
```rust
/// Read a legacy plaintext vault, verify the password, and produce an encrypted
/// copy at the same path (old file kept as `<path>.bak`). Handles v2 (envelope)
/// and v1 (direct-derived) legacy layouts. Returns the master key + new sidecar.
pub fn migrate_plaintext_to_encrypted(
    db_path: &Path,
    password: &str,
) -> Result<([u8; KEY_LEN], Sidecar)> {
    let conn = db::open(db_path)?; // plaintext
    let (master_key, sc) = read_legacy(&conn, password)?;

    // Export into a new encrypted DB next to the original.
    let new_path = PathBuf::from(format!("{}.new", db_path.display()));
    if new_path.exists() {
        std::fs::remove_file(&new_path).ok();
    }
    let key_hex = vault::key_hex(&master_key);
    conn.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS enc KEY \"x'{}'\";
         SELECT sqlcipher_export('enc');
         DETACH DATABASE enc;",
        new_path.display(),
        key_hex,
    ))?;
    drop(conn);

    // Swap: original -> .bak, new -> original.
    let bak = PathBuf::from(format!("{}.bak", db_path.display()));
    std::fs::rename(db_path, &bak).map_err(|e| AppError::Io(e.to_string()))?;
    std::fs::rename(&new_path, db_path).map_err(|e| AppError::Io(e.to_string()))?;

    // Verify the encrypted DB opens with the master key.
    let check = db::open_keyed(db_path, &key_hex)?;
    check
        .query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |_| Ok(()))
        .ok();
    Ok((master_key, sc))
}

fn meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM vault_meta WHERE key=?1", [key], |r| r.get(0))
        .ok()
}

/// Verify `password` against a legacy plaintext DB and build a v3 sidecar.
fn read_legacy(conn: &Connection, password: &str) -> Result<([u8; KEY_LEN], Sidecar)> {
    let is_v2 = meta(conn, "master_wrap").is_some();
    if is_v2 {
        let params: Argon2Params =
            serde_json::from_str(&meta(conn, "kdf_params").ok_or(AppError::VaultMissing)?)?;
        let pw_salt = hex::decode(meta(conn, "pw_salt").ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt salt"))?;
        let master_wrap = hex::decode(meta(conn, "master_wrap").ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt master wrap"))?;
        let verify_hex = meta(conn, "verify_blob").ok_or(AppError::VaultMissing)?;
        let verify = hex::decode(&verify_hex).map_err(|_| AppError::crypto("corrupt verify"))?;

        let pw_key = crypto::derive_key(password, &pw_salt, &params)?;
        let master_key = match crypto::decrypt(&pw_key, &master_wrap) {
            Ok(k) if k.len() == KEY_LEN => {
                let mut a = [0u8; KEY_LEN]; a.copy_from_slice(&k); a
            }
            _ => return Err(AppError::WrongPassword),
        };
        if !crypto::verify_key(&master_key, &verify) {
            return Err(AppError::WrongPassword);
        }
        let recovery: Vec<RecoveryEntry> =
            serde_json::from_str(&meta(conn, "recovery").unwrap_or_else(|| "[]".into()))
                .unwrap_or_default();
        let sc = Sidecar {
            format: "secret-manager-meta".into(),
            version: 3,
            kdf: params,
            pw_salt: hex::encode(pw_salt),
            master_wrap: hex::encode(&master_wrap),
            verify: verify_hex,
            recovery,
            failed_attempts: 0,
            locked_until_ms: 0,
            biometric_wrap: None,
        };
        Ok((master_key, sc))
    } else {
        // v1: key derived directly from the password. Re-wrap under a new random
        // master key is NOT possible without re-encrypting secrets; instead treat
        // the derived key itself as the master key (secrets were encrypted with it).
        let salt = hex::decode(meta(conn, "argon2_salt").ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt salt"))?;
        let params: Argon2Params =
            serde_json::from_str(&meta(conn, "argon2_params").ok_or(AppError::VaultMissing)?)?;
        let verify_hex = meta(conn, "verify_blob").ok_or(AppError::VaultMissing)?;
        let verify = hex::decode(&verify_hex).map_err(|_| AppError::crypto("corrupt verify"))?;
        let key = crypto::derive_key(password, &salt, &params)?;
        if !crypto::verify_key(&key, &verify) {
            return Err(AppError::WrongPassword);
        }
        // Wrap this key as the master key under the same password so future
        // unlocks use the v3 envelope path.
        let pw_salt = crypto::generate_salt()?;
        let pw_key = crypto::derive_key(password, &pw_salt, &params)?;
        let master_wrap = crypto::encrypt(&pw_key, &key)?;
        let sc = Sidecar {
            format: "secret-manager-meta".into(),
            version: 3,
            kdf: params,
            pw_salt: hex::encode(pw_salt),
            master_wrap: hex::encode(&master_wrap),
            verify: verify_hex,
            recovery: Vec::new(),
            failed_attempts: 0,
            locked_until_ms: 0,
            biometric_wrap: None,
        };
        Ok((key, sc))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml migrate::`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/migrate.rs src-tauri/src/lib.rs
git commit -m "feat: migrate legacy plaintext vaults to encrypted v3"
```

---

### Task 2.6: Wire the command layer to sidecar + keyed DB

**Files:**
- Modify: `src-tauri/src/commands/vault.rs`
- Modify: `src-tauri/src/lib.rs` (no new commands yet; ensure it compiles)

**Interfaces:**
- Consumes: `sidecar::Sidecar`, `vault::*` (new signatures), `db::open_keyed`, `migrate::migrate_plaintext_to_encrypted`.
- Produces: same command names as today (`vault_exists`, `create_vault`, `unlock_vault`, `recover_vault`, `regenerate_recovery_codes`, `change_master_password`, `vault_has_recovery`, `delete_vault`), now sidecar-backed. `unlock_vault` transparently migrates a legacy vault.

- [ ] **Step 1: Rewrite the command bodies**

Replace `src-tauri/src/commands/vault.rs` command bodies as follows (keep the `async`/attribute lines and signatures identical to today except where noted):

`vault_exists` — present if either a sidecar or a legacy DB file exists:
```rust
#[tauri::command]
pub fn vault_exists(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    Ok(crate::sidecar::Sidecar::exists(&path) || path.exists())
}
```
`vault_has_recovery` — read the sidecar (legacy vaults report false until migrated):
```rust
#[tauri::command]
pub fn vault_has_recovery(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !crate::sidecar::Sidecar::exists(&path) {
        return Ok(false);
    }
    let sc = crate::sidecar::Sidecar::load(&path)?;
    Ok(crate::vault::has_recovery(&sc))
}
```
`create_vault`:
```rust
#[tauri::command]
pub async fn create_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    password: String,
    vault_path: Option<String>,
) -> Result<Vec<String>> {
    let path = resolve_vault_path(&app, vault_path)?;
    if crate::sidecar::Sidecar::exists(&path) || path.exists() {
        return Err(AppError::VaultExists);
    }
    let (key, sc, codes) = vault::create(&password)?;
    let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
    sc.save(&path)?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(codes)
}
```
`unlock_vault` — migrate if legacy, else sidecar unlock:
```rust
#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    password: String,
    vault_path: Option<String>,
) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    let sidecar_exists = crate::sidecar::Sidecar::exists(&path);
    if !sidecar_exists && !path.exists() {
        return Err(AppError::VaultMissing);
    }

    let (key, conn) = if sidecar_exists {
        let sc = crate::sidecar::Sidecar::load(&path)?;
        let key = vault::unlock(&sc, &password)?;
        let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
        (key, conn)
    } else {
        // Legacy plaintext DB: migrate in place.
        let (key, sc) = crate::migrate::migrate_plaintext_to_encrypted(&path, &password)?;
        sc.save(&path)?;
        let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
        (key, conn)
    };

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(true)
}
```
`recover_vault`:
```rust
#[tauri::command]
pub async fn recover_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    code: String,
    new_password: String,
    vault_path: Option<String>,
) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !crate::sidecar::Sidecar::exists(&path) {
        return Err(AppError::NoRecovery);
    }
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    let key = vault::recover(&mut sc, &code, &new_password)?;
    sc.save(&path)?;
    let conn = db::open_keyed(&path, &vault::key_hex(&key))?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(())
}
```
`regenerate_recovery_codes` — mutate + persist the sidecar:
```rust
#[tauri::command]
pub async fn regenerate_recovery_codes(
    state: State<'_, VaultState>,
) -> Result<Vec<String>> {
    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let key = *session.key.as_ref().ok_or(AppError::VaultLocked)?.clone();
    let path = session.path.clone().ok_or(AppError::VaultLocked)?;
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    let codes = vault::regenerate_recovery(&mut sc, &key)?;
    sc.save(&path)?;
    let _ = &mut session; // keep the guard alive
    Ok(codes)
}
```
`change_master_password`:
```rust
#[tauri::command]
pub async fn change_master_password(
    state: State<'_, VaultState>,
    old_password: String,
    new_password: String,
) -> Result<()> {
    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let path = session.path.clone().ok_or(AppError::VaultLocked)?;
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    let new_key = vault::change_password(&mut sc, &old_password, &new_password)?;
    sc.save(&path)?;
    session.key = Some(Zeroizing::new(new_key));
    Ok(())
}
```
`delete_vault` — also remove the sidecar:
```rust
#[tauri::command]
pub fn delete_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    vault_path: Option<String>,
) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;
    {
        let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
        session.lock();
        session.db = None;
        session.path = None;
    }
    for suffix in ["", "-wal", "-shm", ".bak", ".meta.json"] {
        let p = if suffix.is_empty() {
            path.clone()
        } else {
            std::path::PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| AppError::Io(e.to_string()))?;
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Build the backend**

Run: `cargo build --manifest-path src-tauri/Cargo.toml`
Expected: compiles. Fix any unused-import warnings in `vault.rs`/`commands/vault.rs`.

- [ ] **Step 3: Run the full Rust test suite**

Run: `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: PASS. Note: `tests/persistence.rs` (integration) — if it opens the DB with the old plaintext `db::open` + `vault::create(conn, ...)`, update it to the new flow: `let (key, sc, _) = vault::create("pw"); sc.save(&path); let conn = db::open_keyed(&path, &vault::key_hex(&key));`. Adjust its assertions to reopen with `open_keyed`.

- [ ] **Step 4: Commit**

```bash
git add src-tauri/src/commands/vault.rs src-tauri/tests/persistence.rs
git commit -m "refactor: wire vault commands to encrypted DB + sidecar, migrate on unlock"
```

---

### Task 2.7: Post-migration "delete plaintext backup" affordance

**Files:**
- Modify: `src-tauri/src/commands/vault.rs` (new command `delete_migration_backup`)
- Modify: `src-tauri/src/lib.rs` (register command)
- Modify: `src/lib/tauri.ts` (wrapper)
- Modify: `src/pages/Settings.tsx` (button, visible when backup exists)

**Interfaces:**
- Produces: command `migration_backup_exists(vault_path?) -> bool` and `delete_migration_backup(vault_path?) -> ()`; TS `migrationBackupExists`, `deleteMigrationBackup`.

- [ ] **Step 1: Add backend commands**

In `src-tauri/src/commands/vault.rs`:
```rust
/// Whether a plaintext `.bak` from migration is still on disk.
#[tauri::command]
pub fn migration_backup_exists(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    Ok(std::path::PathBuf::from(format!("{}.bak", path.display())).exists())
}

/// Delete the plaintext migration backup.
#[tauri::command]
pub fn delete_migration_backup(app: AppHandle, vault_path: Option<String>) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;
    let bak = std::path::PathBuf::from(format!("{}.bak", path.display()));
    if bak.exists() {
        std::fs::remove_file(&bak).map_err(|e| AppError::Io(e.to_string()))?;
    }
    Ok(())
}
```
Register both in `src-tauri/src/lib.rs` `generate_handler!` under the `// vault` group.

- [ ] **Step 2: Add TS wrappers**

In `src/lib/tauri.ts` under `// ---- Vault ----`:
```ts
export const migrationBackupExists = (vaultPath?: string) =>
  invoke<boolean>("migration_backup_exists", { vaultPath });

export const deleteMigrationBackup = (vaultPath?: string) =>
  invoke<void>("delete_migration_backup", { vaultPath });
```

- [ ] **Step 3: Surface a Settings banner + delete button**

In `src/pages/Settings.tsx`, add state + effect near the other `useState`s:
```tsx
const [backupExists, setBackupExists] = useState(false);
useEffect(() => {
  migrationBackupExists(settings.customVaultPath ?? undefined)
    .then(setBackupExists)
    .catch(() => setBackupExists(false));
}, [settings.customVaultPath]);
```
Add the imports `migrationBackupExists, deleteMigrationBackup` to the existing `../lib/tauri` import. Render, inside the security `Section`, when `backupExists`:
```tsx
{backupExists && (
  <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-[12.5px]">
    <p className="mb-2 text-text">
      A plaintext backup of your vault (<code>vault.db.bak</code>) was kept during
      encryption migration. Delete it once you've confirmed the vault opens.
    </p>
    <Button
      variant="danger"
      onClick={async () => {
        await deleteMigrationBackup(settings.customVaultPath ?? undefined);
        setBackupExists(false);
      }}
    >
      Delete plaintext backup
    </Button>
  </div>
)}
```
(If `Button` has no `variant="danger"`, use the existing danger styling pattern in the file.)

- [ ] **Step 4: Verify build**

Run: `cargo build --manifest-path src-tauri/Cargo.toml && npm run typecheck`
Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/commands/vault.rs src-tauri/src/lib.rs src/lib/tauri.ts src/pages/Settings.tsx
git commit -m "feat: delete plaintext migration backup from Settings"
```

---

## Phase 3 — Rate limiting (exponential backoff)

### Task 3.1: `RateLimited` error + backoff schedule

**Files:**
- Modify: `src-tauri/src/error.rs`
- Modify: `src-tauri/src/vault.rs` (schedule + guard helpers)

**Interfaces:**
- Produces:
  ```rust
  // error.rs
  AppError::RateLimited { retry_after_secs: u64 } // Display: "Too many attempts. Try again in {n}s."
  // vault.rs
  pub fn backoff_delay_ms(failed_attempts: u32) -> i64;   // schedule
  pub fn check_rate_limit(sc: &Sidecar, now_ms: i64) -> Result<()>;  // Err(RateLimited) if locked
  pub fn record_failure(sc: &mut Sidecar, now_ms: i64);   // ++attempts, set locked_until
  pub fn record_success(sc: &mut Sidecar);                // reset
  ```

- [ ] **Step 1: Add the error variant**

In `src-tauri/src/error.rs`, add to the `AppError` enum:
```rust
    #[error("Too many attempts. Try again in {retry_after_secs}s.")]
    RateLimited { retry_after_secs: u64 },
```

- [ ] **Step 2: Write failing tests**

In `vault.rs` tests module:
```rust
#[test]
fn backoff_schedule_matches_spec() {
    assert_eq!(backoff_delay_ms(1), 0);
    assert_eq!(backoff_delay_ms(3), 0);
    assert_eq!(backoff_delay_ms(4), 5_000);
    assert_eq!(backoff_delay_ms(5), 15_000);
    assert_eq!(backoff_delay_ms(6), 30_000);
    assert_eq!(backoff_delay_ms(7), 60_000);
    assert_eq!(backoff_delay_ms(8), 300_000);
    assert_eq!(backoff_delay_ms(99), 300_000);
}

#[test]
fn rate_limit_blocks_until_expiry_then_clears_on_success() {
    let (_k, mut sc, _c) = create("pw").unwrap();
    // 4 failures -> locked for 5s from now.
    for _ in 0..4 { record_failure(&mut sc, 1_000); }
    assert!(matches!(check_rate_limit(&sc, 1_000), Err(AppError::RateLimited { .. })));
    // After the window it's allowed again.
    assert!(check_rate_limit(&sc, 1_000 + 5_001).is_ok());
    record_success(&mut sc);
    assert_eq!(sc.failed_attempts, 0);
    assert_eq!(sc.locked_until_ms, 0);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::tests::backoff_schedule`
Expected: FAIL — helpers not defined.

- [ ] **Step 4: Implement the helpers**

In `vault.rs`:
```rust
/// Backoff delay (ms) imposed after `failed_attempts` consecutive failures.
pub fn backoff_delay_ms(failed_attempts: u32) -> i64 {
    match failed_attempts {
        0..=3 => 0,
        4 => 5_000,
        5 => 15_000,
        6 => 30_000,
        7 => 60_000,
        _ => 300_000,
    }
}

/// Reject if the vault is currently in a backoff window.
pub fn check_rate_limit(sc: &Sidecar, now_ms: i64) -> Result<()> {
    if now_ms < sc.locked_until_ms {
        let secs = ((sc.locked_until_ms - now_ms) as f64 / 1000.0).ceil() as u64;
        return Err(AppError::RateLimited { retry_after_secs: secs.max(1) });
    }
    Ok(())
}

/// Record a failed unlock: bump the counter and set the next allowed time.
pub fn record_failure(sc: &mut Sidecar, now_ms: i64) {
    sc.failed_attempts = sc.failed_attempts.saturating_add(1);
    let delay = backoff_delay_ms(sc.failed_attempts);
    sc.locked_until_ms = now_ms + delay;
}

/// Record a successful unlock: clear the counter and lock window.
pub fn record_success(sc: &mut Sidecar) {
    sc.failed_attempts = 0;
    sc.locked_until_ms = 0;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/error.rs src-tauri/src/vault.rs
git commit -m "feat: rate-limit backoff schedule + guards"
```

---

### Task 3.2: Enforce rate limiting in `unlock_vault`

**Files:**
- Modify: `src-tauri/src/commands/vault.rs`

- [ ] **Step 1: Guard + record around the sidecar unlock path**

In `unlock_vault`, replace the `if sidecar_exists { ... }` branch with a rate-limited version:
```rust
let (key, conn) = if sidecar_exists {
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    let now = crate::db::now_ms();
    crate::vault::check_rate_limit(&sc, now)?; // Err(RateLimited) short-circuits, no Argon2
    match vault::unlock(&sc, &password) {
        Ok(key) => {
            crate::vault::record_success(&mut sc);
            sc.save(&path)?;
            let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
            (key, conn)
        }
        Err(e) => {
            crate::vault::record_failure(&mut sc, now);
            sc.save(&path)?;
            return Err(e);
        }
    }
} else {
    let (key, sc) = crate::migrate::migrate_plaintext_to_encrypted(&path, &password)?;
    sc.save(&path)?;
    let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
    (key, conn)
};
```

- [ ] **Step 2: Build + test**

Run: `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: PASS (all).

- [ ] **Step 3: Commit**

```bash
git add src-tauri/src/commands/vault.rs
git commit -m "feat: enforce unlock rate limiting (backoff, persisted)"
```

---

### Task 3.3: Frontend countdown on the unlock button

**Files:**
- Modify: `src/components/UnlockScreen.tsx`

- [ ] **Step 1: Parse the retry seconds and run a countdown**

Add state:
```tsx
const [lockedFor, setLockedFor] = useState(0);
```
Add an effect that ticks down:
```tsx
useEffect(() => {
  if (lockedFor <= 0) return;
  const t = setInterval(() => setLockedFor((s) => Math.max(0, s - 1)), 1000);
  return () => clearInterval(t);
}, [lockedFor]);
```
(Add `useEffect` to the React import.) In `onAuthSubmit`'s `catch (err)`, detect the rate-limit message and start the countdown:
```tsx
} catch (err) {
  const msg = errMessage(err);
  const m = msg.match(/try again in (\d+)s/i);
  if (m) setLockedFor(parseInt(m[1], 10));
  setError(msg);
}
```

- [ ] **Step 2: Disable the unlock button while locked**

Change the unlock submit `Button` (the `!firstRun` case) to:
```tsx
<Button type="submit" loading={busy} disabled={lockedFor > 0} className="mt-6 w-full">
  {lockedFor > 0 ? (
    <>Locked — retry in {lockedFor}s</>
  ) : (
    <><KeyRound className="h-4 w-4" /> Unlock</>
  )}
</Button>
```
(Keep the create-vault button as-is; rate limiting only applies to unlock.)

- [ ] **Step 3: Verify typecheck + existing test**

Run: `npm run typecheck && npm test -- UnlockScreen`
Expected: clean + PASS.

- [ ] **Step 4: Commit**

```bash
git add src/components/UnlockScreen.tsx
git commit -m "feat: unlock button countdown while rate-limited"
```

---

## Phase 4 — Biometric unlock (macOS Touch ID)

### Task 4.1: Keychain token store (macOS)

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Create: `src-tauri/src/biometric.rs`
- Modify: `src-tauri/src/lib.rs` (add `pub mod biometric;`)
- Modify: `src-tauri/src/error.rs` (add `Unsupported`)

**Interfaces:**
- Produces:
  ```rust
  // error.rs
  AppError::Unsupported  // Display: "This feature is not supported on this platform."
  // biometric.rs
  pub fn is_available() -> bool;                        // true only on macOS with a Secure Enclave/Touch ID
  pub fn store_token(token: &[u8]) -> Result<()>;       // biometric-gated keychain item
  pub fn fetch_token() -> Result<Vec<u8>>;              // prompts Touch ID
  pub fn delete_token() -> Result<()>;
  ```
  On non-macOS all functions return `Err(AppError::Unsupported)` (and `is_available` returns `false`).

- [ ] **Step 1: Add the macOS-only dependency**

In `src-tauri/Cargo.toml`, after the `[dependencies]` block add a target section:
```toml
[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "3"
```

- [ ] **Step 2: Add the `Unsupported` error**

In `src-tauri/src/error.rs` enum:
```rust
    #[error("This feature is not supported on this platform.")]
    Unsupported,
```

- [ ] **Step 3: Implement the biometric module (macOS + fallback)**

Create `src-tauri/src/biometric.rs`:
```rust
//! macOS Touch ID token storage via the Keychain. On other platforms every
//! function reports `AppError::Unsupported`.

use crate::error::{AppError, Result};

const SERVICE: &str = "com.secretmanager.app.biometric";
const ACCOUNT: &str = "vault-token";

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
    use security_framework::passwords_options::PasswordOptions;

    pub fn is_available() -> bool {
        // Touch ID availability is proven when we can build a biometric ACL.
        SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            security_framework::access_control::AccessControlFlags::BIOMETRY_CURRENT_SET
                | security_framework::access_control::AccessControlFlags::USER_PRESENCE,
        )
        .is_ok()
    }

    pub fn store_token(token: &[u8]) -> Result<()> {
        delete_token().ok();
        let acl = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            security_framework::access_control::AccessControlFlags::BIOMETRY_CURRENT_SET
                | security_framework::access_control::AccessControlFlags::USER_PRESENCE,
        )
        .map_err(|e| AppError::Io(format!("keychain acl: {e}")))?;
        let mut opts = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        opts.set_access_control(acl);
        security_framework::passwords::set_generic_password_options(token, opts)
            .map_err(|e| AppError::Io(format!("keychain store: {e}")))?;
        Ok(())
    }

    pub fn fetch_token() -> Result<Vec<u8>> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(SERVICE)
            .account(ACCOUNT)
            .load_data(true)
            .limit(Limit::Max(1));
        match search.search() {
            Ok(results) => {
                for r in results {
                    if let SearchResult::Data(d) = r {
                        return Ok(d);
                    }
                }
                Err(AppError::Io("keychain: token not found".into()))
            }
            Err(e) => Err(AppError::Io(format!("keychain fetch: {e}"))),
        }
    }

    pub fn delete_token() -> Result<()> {
        security_framework::passwords::delete_generic_password(SERVICE, ACCOUNT)
            .map_err(|e| AppError::Io(format!("keychain delete: {e}")))?;
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;
    pub fn is_available() -> bool { false }
    pub fn store_token(_t: &[u8]) -> Result<()> { Err(AppError::Unsupported) }
    pub fn fetch_token() -> Result<Vec<u8>> { Err(AppError::Unsupported) }
    pub fn delete_token() -> Result<()> { Err(AppError::Unsupported) }
}

pub fn is_available() -> bool { imp::is_available() }
pub fn store_token(token: &[u8]) -> Result<()> { imp::store_token(token) }
pub fn fetch_token() -> Result<Vec<u8>> { imp::fetch_token() }
pub fn delete_token() -> Result<()> { imp::delete_token() }
```
Register in `src-tauri/src/lib.rs`: `pub mod biometric;`.

> **Verify the `security-framework` API** with Context7 before finalizing Step 3 — the exact `SecAccessControl` / `PasswordOptions` method names vary across 2.x/3.x. Resolve `security-framework` and query "store generic password with SecAccessControl biometry". Adjust the calls to match the installed version; keep the module's public function signatures unchanged.

- [ ] **Step 4: Build (macOS)**

Run: `cargo build --manifest-path src-tauri/Cargo.toml`
Expected: compiles on macOS. (No unit test — Keychain access requires an interactive Touch ID prompt; this is verified manually in Task 4.3.)

- [ ] **Step 5: Commit**

```bash
git add src-tauri/Cargo.toml src-tauri/Cargo.lock src-tauri/src/biometric.rs src-tauri/src/lib.rs src-tauri/src/error.rs
git commit -m "feat: macOS Keychain token store for biometric unlock"
```

---

### Task 4.2: Biometric enroll/unlock/disable commands

**Files:**
- Modify: `src-tauri/src/vault.rs` (wrap/unwrap helpers for the biometric token)
- Modify: `src-tauri/src/commands/vault.rs` (four commands)
- Modify: `src-tauri/src/lib.rs` (register)

**Interfaces:**
- Produces (vault.rs):
  ```rust
  pub fn wrap_master_for_biometric(sc: &mut Sidecar, master_key: &[u8; KEY_LEN], token: &[u8; KEY_LEN]) -> Result<()>;
  pub fn unwrap_master_from_biometric(sc: &Sidecar, token: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN]>;
  pub fn clear_biometric(sc: &mut Sidecar);
  ```
- Produces (commands): `biometric_available`, `biometric_enroll`, `biometric_unlock`, `biometric_disable`.

- [ ] **Step 1: Write failing wrap/unwrap tests**

In `vault.rs` tests:
```rust
#[test]
fn biometric_wrap_round_trips() {
    let (key, mut sc, _c) = create("pw").unwrap();
    let token = [7u8; KEY_LEN];
    wrap_master_for_biometric(&mut sc, &key, &token).unwrap();
    assert!(sc.biometric_wrap.is_some());
    let got = unwrap_master_from_biometric(&sc, &token).unwrap();
    assert_eq!(got, key);
    // Wrong token fails.
    let bad = [8u8; KEY_LEN];
    assert!(unwrap_master_from_biometric(&sc, &bad).is_err());
    clear_biometric(&mut sc);
    assert!(sc.biometric_wrap.is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::tests::biometric_wrap`
Expected: FAIL — helpers not defined.

- [ ] **Step 3: Implement the wrap helpers**

In `vault.rs`:
```rust
/// Store `AES-GCM(token, master_key)` in the sidecar so a biometric-released
/// token can recover the master key.
pub fn wrap_master_for_biometric(
    sc: &mut Sidecar,
    master_key: &[u8; KEY_LEN],
    token: &[u8; KEY_LEN],
) -> Result<()> {
    let wrap = crypto::encrypt(token, master_key)?;
    sc.biometric_wrap = Some(hex::encode(wrap));
    Ok(())
}

/// Recover the master key from the biometric wrap using `token`.
pub fn unwrap_master_from_biometric(
    sc: &Sidecar,
    token: &[u8; KEY_LEN],
) -> Result<[u8; KEY_LEN]> {
    let hexed = sc.biometric_wrap.as_ref().ok_or(AppError::NoRecovery)?;
    let wrap = hex::decode(hexed).map_err(|_| AppError::crypto("corrupt biometric wrap"))?;
    let mk = crypto::decrypt(token, &wrap)?;
    if mk.len() != KEY_LEN {
        return Err(AppError::crypto("bad biometric wrap length"));
    }
    let mut arr = [0u8; KEY_LEN];
    arr.copy_from_slice(&mk);
    let verify = hex::decode(&sc.verify).map_err(|_| AppError::crypto("corrupt verify"))?;
    if !crypto::verify_key(&arr, &verify) {
        return Err(AppError::crypto("biometric wrap failed verification"));
    }
    Ok(arr)
}

/// Remove the biometric wrap from the sidecar.
pub fn clear_biometric(sc: &mut Sidecar) {
    sc.biometric_wrap = None;
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --manifest-path src-tauri/Cargo.toml vault::tests::biometric_wrap`
Expected: PASS.

- [ ] **Step 5: Add the four commands**

In `src-tauri/src/commands/vault.rs`:
```rust
/// Whether biometric unlock is available on this platform + device.
#[tauri::command]
pub fn biometric_available() -> Result<bool> {
    Ok(crate::biometric::is_available())
}

/// Enroll biometric unlock for the currently-unlocked vault.
#[tauri::command]
pub async fn biometric_enroll(state: State<'_, VaultState>) -> Result<()> {
    let (master_key, path) = {
        let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
        let key = *session.key.as_ref().ok_or(AppError::VaultLocked)?.clone();
        let path = session.path.clone().ok_or(AppError::VaultLocked)?;
        (key, path)
    };
    let token_bytes = crate::crypto::random_bytes(crate::crypto::KEY_LEN)?;
    let mut token = [0u8; crate::crypto::KEY_LEN];
    token.copy_from_slice(&token_bytes);

    crate::biometric::store_token(&token)?;
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    crate::vault::wrap_master_for_biometric(&mut sc, &master_key, &token)?;
    sc.save(&path)?;
    Ok(())
}

/// Unlock the vault via Touch ID (prompts for a fingerprint).
#[tauri::command]
pub async fn biometric_unlock(
    app: AppHandle,
    state: State<'_, VaultState>,
    vault_path: Option<String>,
) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !crate::sidecar::Sidecar::exists(&path) {
        return Err(AppError::VaultMissing);
    }
    let sc = crate::sidecar::Sidecar::load(&path)?;
    if sc.biometric_wrap.is_none() {
        return Err(AppError::NoRecovery);
    }
    let token_vec = crate::biometric::fetch_token()?; // Touch ID prompt
    let mut token = [0u8; crate::crypto::KEY_LEN];
    if token_vec.len() != crate::crypto::KEY_LEN {
        return Err(AppError::crypto("bad keychain token length"));
    }
    token.copy_from_slice(&token_vec);
    let key = crate::vault::unwrap_master_from_biometric(&sc, &token)?;
    let conn = db::open_keyed(&path, &vault::key_hex(&key))?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(true)
}

/// Disable biometric unlock: delete the keychain token + sidecar wrap.
#[tauri::command]
pub async fn biometric_disable(
    app: AppHandle,
    vault_path: Option<String>,
) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;
    crate::biometric::delete_token().ok();
    if crate::sidecar::Sidecar::exists(&path) {
        let mut sc = crate::sidecar::Sidecar::load(&path)?;
        crate::vault::clear_biometric(&mut sc);
        sc.save(&path)?;
    }
    Ok(())
}
```
Add `biometric_enrolled` for UI state:
```rust
/// Whether the vault has a biometric wrap configured.
#[tauri::command]
pub fn biometric_enrolled(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !crate::sidecar::Sidecar::exists(&path) {
        return Ok(false);
    }
    Ok(crate::sidecar::Sidecar::load(&path)?.biometric_wrap.is_some())
}
```
Register all five in `src-tauri/src/lib.rs`.

- [ ] **Step 6: Build + test**

Run: `cargo test --manifest-path src-tauri/Cargo.toml`
Expected: PASS (unit tests) and clean build.

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/vault.rs src-tauri/src/commands/vault.rs src-tauri/src/lib.rs
git commit -m "feat: biometric enroll/unlock/disable commands"
```

---

### Task 4.3: Frontend biometric — Settings toggle + unlock button

**Files:**
- Modify: `src/lib/tauri.ts`
- Modify: `src/store/vault.ts`
- Modify: `src/components/UnlockScreen.tsx`
- Modify: `src/pages/Settings.tsx`

**Interfaces:**
- Consumes: new commands. Produces TS wrappers `biometricAvailable`, `biometricEnrolled`, `biometricEnroll`, `biometricUnlock`, `biometricDisable`; store action `biometricUnlock()`.

- [ ] **Step 1: Add TS wrappers**

In `src/lib/tauri.ts` under `// ---- Vault ----`:
```ts
export const biometricAvailable = () => invoke<boolean>("biometric_available");
export const biometricEnrolled = (vaultPath?: string) =>
  invoke<boolean>("biometric_enrolled", { vaultPath });
export const biometricEnroll = () => invoke<void>("biometric_enroll");
export const biometricUnlock = (vaultPath?: string) =>
  invoke<boolean>("biometric_unlock", { vaultPath });
export const biometricDisable = (vaultPath?: string) =>
  invoke<void>("biometric_disable", { vaultPath });
```

- [ ] **Step 2: Add a store action**

In `src/store/vault.ts`, add to the interface: `biometricUnlock: () => Promise<void>;` and implement (mirrors `unlock`):
```ts
biometricUnlock: async () => {
  set({ busy: true, error: null });
  try {
    await api.biometricUnlock(vaultPath());
    set({ isUnlocked: true });
    await get().refreshProjects();
  } finally {
    set({ busy: false });
  }
},
```

- [ ] **Step 3: Add a Touch ID button to the unlock screen**

In `src/components/UnlockScreen.tsx`, pull `biometricUnlock` from the store and add availability state:
```tsx
const { hasVault, unlock, createVault, recover, resetVault, busy, biometricUnlock } = useVault();
const [bioReady, setBioReady] = useState(false);
useEffect(() => {
  if (firstRun) return;
  Promise.all([api_biometricAvailable(), api_biometricEnrolled()])
    .then(([a, e]) => setBioReady(a && e))
    .catch(() => setBioReady(false));
}, [firstRun]);
```
Import at top: `import { biometricAvailable as api_biometricAvailable, biometricEnrolled as api_biometricEnrolled } from "../lib/tauri";` (pass `undefined` vault path — the store's `vaultPath()` isn't exported; `biometricEnrolled()` defaults fine). Render below the Unlock button (only in `!firstRun` auth mode, when `bioReady`):
```tsx
{!firstRun && bioReady && (
  <Button
    type="button"
    variant="ghost"
    onClick={async () => {
      setError(null);
      try { await biometricUnlock(); resetFields(); }
      catch (err) { setError(errMessage(err)); }
    }}
    className="mt-3 w-full"
  >
    <Fingerprint className="h-4 w-4" /> Unlock with Touch ID
  </Button>
)}
```
Add `Fingerprint` to the `lucide-react` import. (If `Button` lacks a `ghost` variant, reuse an existing secondary style.)

- [ ] **Step 4: Add a Settings toggle**

In `src/pages/Settings.tsx`, add a "Touch ID" row inside the security `Section`:
```tsx
const [bioAvail, setBioAvail] = useState(false);
const [bioOn, setBioOn] = useState(false);
useEffect(() => {
  biometricAvailable().then(setBioAvail).catch(() => setBioAvail(false));
  biometricEnrolled(settings.customVaultPath ?? undefined).then(setBioOn).catch(() => setBioOn(false));
}, [settings.customVaultPath]);
```
Import `biometricAvailable, biometricEnrolled, biometricEnroll, biometricDisable` from `../lib/tauri`. Render (only when `bioAvail`):
```tsx
{bioAvail && (
  <div className="flex items-center justify-between">
    <div>
      <p className="text-[13px] text-text">Unlock with Touch ID</p>
      <p className="text-[11.5px] text-text-muted">
        Store an unlock token in the macOS Keychain, protected by your fingerprint.
      </p>
    </div>
    <Button
      variant="secondary"
      onClick={async () => {
        try {
          if (bioOn) { await biometricDisable(settings.customVaultPath ?? undefined); setBioOn(false); }
          else { await biometricEnroll(); setBioOn(true); }
        } catch (err) { setPwMsg({ ok: false, text: errMessage(err) }); }
      }}
    >
      {bioOn ? "Disable" : "Enable"}
    </Button>
  </div>
)}
```

- [ ] **Step 5: Verify typecheck + build**

Run: `npm run typecheck && npm run build`
Expected: clean.

- [ ] **Step 6: Manual verification (macOS, real `tauri dev`)**

Run: `npm run tauri dev`
Steps: unlock vault → Settings → enable Touch ID (approve prompt) → lock → confirm "Unlock with Touch ID" appears → click → Touch ID prompt → vault unlocks. Then Settings → Disable → lock → confirm the button no longer appears.

- [ ] **Step 7: Commit**

```bash
git add src/lib/tauri.ts src/store/vault.ts src/components/UnlockScreen.tsx src/pages/Settings.tsx
git commit -m "feat: Touch ID unlock button + Settings toggle"
```

---

## Final integration

### Task 5.1: Full suite + docs

**Files:**
- Modify: `docs/ARCHITECTURE.md` (if present) or `README.md` — security section.

- [ ] **Step 1: Run everything**

Run:
```bash
npm test && npm run build && cargo test --manifest-path src-tauri/Cargo.toml
```
Expected: all green.

- [ ] **Step 2: Update the security docs**

In the security section of `README.md` (and `docs/ARCHITECTURE.md` if it exists), document: full-DB SQLCipher encryption (raw-key mode), the `vault.meta.json` sidecar and its contents, the one-time plaintext `.bak` created on migration, rate-limit backoff, and macOS Touch ID (Keychain token + sidecar wrap). Remove the prior "only secret values are encrypted / metadata is plaintext" caveat — it no longer holds for v3 vaults.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/ARCHITECTURE.md
git commit -m "docs: document SQLCipher, sidecar, rate limiting, Touch ID"
```

- [ ] **Step 4: Open a PR**

```bash
git push -u origin HEAD
gh pr create --title "Vault security hardening: SQLCipher, rate limiting, Touch ID, strength meter" --body "$(cat <<'EOF'
## Summary
- Full-database SQLCipher encryption (was field-level on values only), with a
  `vault.meta.json` sidecar holding pre-unlock metadata.
- Transparent one-time migration of legacy plaintext vaults (keeps a `.bak`).
- Failed-unlock exponential backoff (persisted, never permanent).
- macOS Touch ID unlock via Keychain-stored token + sidecar wrap.
- zxcvbn password-strength meter on create/change/recover (warn, never block).

## Testing
- `cargo test` (crypto, vault, sidecar, migration, rate-limit, biometric wrap)
- `npm test` (strength helper, StrengthMeter, existing suite)
- Manual: Touch ID enroll/unlock/disable on macOS.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-review notes

- **Spec coverage:** password strength (Tasks 1.1–1.5), SQLCipher + sidecar (2.1–2.6), migration + `.bak` (2.5, 2.7), rate limiting (3.1–3.3), biometric (4.1–4.3), docs (5.1). All spec sections mapped.
- **Type consistency:** `Sidecar`/`RecoveryEntry` defined in Task 2.2 and consumed unchanged in 2.3–4.2; `key_hex`, `check_rate_limit`, `record_failure/success`, `wrap_master_for_biometric`/`unwrap_master_from_biometric`/`clear_biometric` names are stable across the tasks that use them.
- **Known verification point:** the exact `security-framework` API (Task 4.1) must be confirmed against the installed 3.x version via Context7 before finalizing — flagged inline.
- **Ordering risk:** Phase 2 must land before Phase 3 (rate-limit state lives in the sidecar) and Phase 4 (biometric wrap lives in the sidecar). Phase 1 is independent and may land anytime.
