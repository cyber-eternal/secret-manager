//! macOS Touch ID token storage via the Keychain. On other platforms every
//! function reports `AppError::Unsupported`.
//!
//! ## API note (security-framework v3.7.0)
//!
//! The task brief's original sketch assumed a `set_access_control` method on
//! `ItemAddOptions` (the generic `item::add_item` builder). That method does
//! not exist: `ItemAddOptions` (src/item.rs) only exposes
//! `set_account_name`/`set_access_group`/`set_comment`/`set_description`/
//! `set_label`/`set_location`/`set_service` — there's no ACL hook on it.
//!
//! The real place biometric gating is wired up for *generic passwords* is
//! `security_framework::passwords_options::PasswordOptions`, which has both
//! `set_access_control(SecAccessControl)` and the convenience
//! `set_access_control_options(AccessControlOptions)`. Internally,
//! `passwords::set_generic_password_options` pushes whatever query pairs are
//! on `PasswordOptions` (including `kSecAttrAccessControl`) straight into the
//! `SecItemAdd`/`SecItemUpdate` dictionary, so setting access control on a
//! generic password item is fully supported — just via `PasswordOptions`, not
//! `ItemAddOptions`.

use crate::error::{AppError, Result};

const SERVICE: &str = "com.secretmanager.app.biometric";
const ACCOUNT: &str = "vault-token";

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};

    /// Build the access-control policy used to gate the stored token.
    ///
    /// Prefers `BIOMETRY_CURRENT_SET` over `BIOMETRY_ANY`: `CURRENT_SET`
    /// invalidates the keychain item if the enrolled fingerprints/Face ID set
    /// changes (e.g. a new fingerprint is added, or all are removed and
    /// re-enrolled), which is the stronger policy the spec calls for. It is
    /// combined with `USER_PRESENCE` so a passcode fallback is available if
    /// biometry is temporarily unavailable, matching standard macOS UX for
    /// Touch ID-gated keychain items. Both flags are confirmed present in
    /// `security_framework_sys::access_control` (`kSecAccessControlBiometryCurrentSet`,
    /// `kSecAccessControlUserPresence`) and re-exported via
    /// `passwords_options::AccessControlOptions`.
    fn biometric_access_control() -> Result<SecAccessControl> {
        let flags = AccessControlOptions::BIOMETRY_CURRENT_SET | AccessControlOptions::USER_PRESENCE;
        SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            flags.bits(),
        )
        .map_err(|e| AppError::Io(format!("keychain: failed to build access control: {e}")))
    }

    pub fn is_available() -> bool {
        // Touch ID / Face ID availability is proven when we can construct a
        // biometric access-control policy. This doesn't guarantee enrollment,
        // but a hard failure here means the platform can't support the ACL at
        // all (e.g. no Secure Enclave).
        biometric_access_control().is_ok()
    }

    pub fn store_token(token: &[u8]) -> Result<()> {
        let access = biometric_access_control()?;
        let mut options = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        options.set_access_control(access);
        set_generic_password_options(token, options)
            .map_err(|e| AppError::Io(format!("keychain: failed to store token: {e}")))
    }

    pub fn fetch_token() -> Result<Vec<u8>> {
        // This queries the same service+account as `store_token`. Because the
        // stored item's ACL requires biometry, macOS triggers the Touch ID /
        // Face ID prompt during `SecItemCopyMatching` regardless of which
        // helper issued the query.
        get_generic_password(SERVICE, ACCOUNT)
            .map_err(|e| AppError::Io(format!("keychain: failed to fetch token: {e}")))
    }

    pub fn delete_token() -> Result<()> {
        delete_generic_password(SERVICE, ACCOUNT)
            .map_err(|e| AppError::Io(format!("keychain: failed to delete token: {e}")))
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::*;
    pub fn is_available() -> bool {
        false
    }
    pub fn store_token(_t: &[u8]) -> Result<()> {
        Err(AppError::Unsupported)
    }
    pub fn fetch_token() -> Result<Vec<u8>> {
        Err(AppError::Unsupported)
    }
    pub fn delete_token() -> Result<()> {
        Err(AppError::Unsupported)
    }
}

pub fn is_available() -> bool {
    imp::is_available()
}
pub fn store_token(token: &[u8]) -> Result<()> {
    imp::store_token(token)
}
pub fn fetch_token() -> Result<Vec<u8>> {
    imp::fetch_token()
}
pub fn delete_token() -> Result<()> {
    imp::delete_token()
}
