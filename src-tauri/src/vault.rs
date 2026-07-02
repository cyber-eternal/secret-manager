//! Vault lifecycle: create, unlock, change master password, recovery codes.
//!
//! ## Envelope encryption (vault format v2)
//!
//! A random 32-byte **master key** encrypts every secret value. The master key
//! itself is never stored in the clear; instead it is *wrapped* (encrypted)
//! multiple times:
//!   - once by a key derived from the **master password** (`master_wrap`)
//!   - once by each **recovery code** (`recovery` list)
//!
//! Unlock = derive password key → decrypt `master_wrap` → master key.
//! Recovery = derive a key from a recovery code → decrypt its wrap → master key,
//! then re-wrap under a new password. Because secrets are bound to the master
//! key (not the password), changing the password or recovering only re-wraps the
//! master key — no secret re-encryption needed.
//!
//! ## Legacy format (v1)
//!
//! Older vaults derived the encryption key directly from the password and had no
//! recovery codes. Those still unlock (and can change password by re-encrypting),
//! but cannot use recovery. New vaults are always v2.
//!
//! These functions take a raw `Connection` + secrets so they are unit-testable
//! without Tauri.

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::error::{AppError, Result};
use crate::sidecar::{RecoveryEntry, Sidecar};

/// Number of recovery codes generated per set.
pub const RECOVERY_CODE_COUNT: usize = 8;

/// Render a 32-byte master key as 64 lowercase hex chars for `PRAGMA key`.
pub fn key_hex(master_key: &[u8; KEY_LEN]) -> String {
    hex::encode(master_key)
}

// ---------------------------------------------------------------------------
// Recovery code generation
// ---------------------------------------------------------------------------

/// Generate one human-friendly recovery code: 120 bits of entropy rendered as
/// uppercase hex in dash-separated groups, e.g. `A1B2C-3D4E5-...`.
fn generate_recovery_code() -> Result<String> {
    let bytes = crypto::random_bytes(15)?;
    let hex = hex::encode_upper(bytes); // 30 chars
    let grouped = hex
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-");
    Ok(grouped)
}

/// Normalize a user-entered code (strip dashes/spaces, uppercase) before use.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

/// Build the stored recovery wraps for a fresh set of codes. Returns the
/// plaintext codes (to show the user once) and the wrap entries.
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

// ---------------------------------------------------------------------------
// Create / unlock / change password / recover
// ---------------------------------------------------------------------------

/// Build a fresh v3 vault: random master key, sidecar (password wrap + recovery
/// wraps + verify blob), and the one-time recovery codes. Does not touch disk.
/// Uses the production default Argon2 parameters.
pub fn create(password: &str) -> Result<([u8; KEY_LEN], Sidecar, Vec<String>)> {
    create_with_params(password, Argon2Params::default())
}

/// Like [`create`] but with caller-supplied Argon2 parameters. Exists so tests
/// can use cheap KDF params; production callers use [`create`].
pub fn create_with_params(
    password: &str,
    params: Argon2Params,
) -> Result<([u8; KEY_LEN], Sidecar, Vec<String>)> {
    if password.is_empty() {
        return Err(AppError::Invalid("master password must not be empty".into()));
    }
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

/// `true` if the sidecar has at least one recovery wrap.
pub fn has_recovery(sc: &Sidecar) -> bool {
    !sc.recovery.is_empty()
}

// ---------------------------------------------------------------------------
// Unlock rate limiting (backoff persisted in the sidecar)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Biometric wrap
// ---------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;

    // Cheap KDF params so the suite doesn't pay the ~1s/64MB production cost per
    // `create`. change_password/recover/regenerate read params from `sc.kdf`, so
    // they inherit these automatically.
    fn fast_params() -> Argon2Params {
        Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    #[test]
    fn create_then_unlock_v2() {
        let (k1, sc, codes) = create_with_params("hunter2", fast_params()).unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let k2 = unlock(&sc, "hunter2").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn unlock_wrong_password_fails() {
        let (_k, sc, _codes) = create_with_params("hunter2", fast_params()).unwrap();
        assert!(matches!(unlock(&sc, "wrong"), Err(AppError::WrongPassword)));
    }

    #[test]
    fn change_password_rewraps_same_master_key() {
        let (key, mut sc, _codes) = create_with_params("old-pw", fast_params()).unwrap();
        let new_key = change_password(&mut sc, "old-pw", "new-pw").unwrap();
        assert_eq!(new_key, key, "master key stable across password change");
        assert!(matches!(unlock(&sc, "old-pw"), Err(AppError::WrongPassword)));
        assert_eq!(unlock(&sc, "new-pw").unwrap(), key);
    }

    #[test]
    fn recover_with_code_resets_password() {
        let (key, mut sc, codes) = create_with_params("forgotten", fast_params()).unwrap();
        let entered = codes[2].to_lowercase();
        let mk = recover(&mut sc, &entered, "brand-new-pw").unwrap();
        assert_eq!(mk, key);
        assert!(matches!(unlock(&sc, "forgotten"), Err(AppError::WrongPassword)));
        assert_eq!(unlock(&sc, "brand-new-pw").unwrap(), key);
    }

    #[test]
    fn recover_with_bad_code_fails() {
        let (_key, mut sc, _codes) = create_with_params("pw", fast_params()).unwrap();
        assert!(matches!(
            recover(&mut sc, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", "new"),
            Err(AppError::WrongRecoveryCode)
        ));
    }

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
        let (_k, mut sc, _c) = create_with_params("pw", fast_params()).unwrap();
        // 4 failures -> locked for 5s from now.
        for _ in 0..4 { record_failure(&mut sc, 1_000); }
        assert!(matches!(check_rate_limit(&sc, 1_000), Err(AppError::RateLimited { .. })));
        // After the window it's allowed again.
        assert!(check_rate_limit(&sc, 1_000 + 5_001).is_ok());
        record_success(&mut sc);
        assert_eq!(sc.failed_attempts, 0);
        assert_eq!(sc.locked_until_ms, 0);
    }

    #[test]
    fn biometric_wrap_round_trips() {
        let (key, mut sc, _c) = create_with_params("pw", fast_params()).unwrap();
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

    #[test]
    fn regenerate_recovery_invalidates_old_codes() {
        let (key, mut sc, _old_codes) = create_with_params("pw", fast_params()).unwrap();
        let new_codes = regenerate_recovery(&mut sc, &key).unwrap();
        assert_eq!(new_codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(recover(&mut sc, &new_codes[0], "pw2").unwrap(), key);
        // Re-fetch: after recover, sc is mutated; use a fresh vault for the old-code check.
        let (k2, mut sc2, old2) = create_with_params("pw", fast_params()).unwrap();
        let regen = regenerate_recovery(&mut sc2, &k2).unwrap();
        assert!(!regen.is_empty());
        assert!(matches!(
            recover(&mut sc2, &old2[0], "pw3"),
            Err(AppError::WrongRecoveryCode)
        ));
    }
}
