//! Integration test: a vault on disk survives a "restart" (reopening the file)
//! and secrets remain decryptable. Mirrors the Phase 1 acceptance criteria.

use secret_manager_lib::{db, repo, sidecar::Sidecar, vault};

#[test]
fn vault_persists_across_reopen() {
    let dir = std::env::temp_dir().join(format!("sm-test-{}", uuid_like()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.db");

    let project_id;
    let secret_id;

    // --- First "session": create vault, add data ---
    {
        let (key, sc, _codes) = vault::create("master-pw").unwrap();
        let conn = db::open_keyed(&path, &vault::key_hex(&key)).unwrap();
        sc.save(&path).unwrap();
        let p = repo::create_project(&conn, "backend", Some("api server")).unwrap();
        let s = repo::add_secret(
            &conn,
            &key,
            &p.id,
            "DATABASE_URL",
            "postgres://localhost/app",
            Some("primary db"),
            &["db".into(), "prod".into()],
        )
        .unwrap();
        project_id = p.id;
        secret_id = s.id;
    } // conn dropped — simulates app close

    // --- Second "session": reopen the same file, unlock, read back ---
    {
        assert!(Sidecar::exists(&path));
        let sc = Sidecar::load(&path).unwrap();

        // Wrong password is rejected.
        assert!(vault::unlock(&sc, "nope").is_err());

        let key = vault::unlock(&sc, "master-pw").unwrap();
        let conn = db::open_keyed(&path, &vault::key_hex(&key)).unwrap();

        let projects = repo::list_projects(&conn).unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].id, project_id);

        let secret = repo::get_secret(&conn, &key, &secret_id).unwrap();
        assert_eq!(secret.key, "DATABASE_URL");
        assert_eq!(secret.value, "postgres://localhost/app");
        assert_eq!(secret.tags, vec!["db".to_string(), "prod".to_string()]);

        // Search works on the reopened vault.
        let hits = repo::search_secrets(&conn, "DATABASE", None, None).unwrap();
        assert_eq!(hits.len(), 1);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Tiny unique-ish suffix without pulling uuid into the test target directly.
fn uuid_like() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}
