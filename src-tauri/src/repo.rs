//! Data-access layer for projects, secrets, and tags.
//!
//! Secret values are encrypted with the vault key on write and decrypted on
//! read. Everything else (project names, secret keys, tag names) is stored in
//! plaintext per the field-level encryption design in ARCHITECTURE.md.

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::crypto::{self, KEY_LEN};
use crate::db::now_ms;
use crate::error::{AppError, Result};
use crate::models::{Project, Secret, SecretMeta, Tag};

fn new_id() -> String {
    Uuid::new_v4().to_string()
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

pub fn create_project(conn: &Connection, name: &str, description: Option<&str>) -> Result<Project> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::Invalid("project name must not be empty".into()));
    }
    let id = new_id();
    let now = now_ms();
    conn.execute(
        "INSERT INTO projects(id, name, description, created_at, updated_at)
         VALUES(?1, ?2, ?3, ?4, ?4)",
        params![id, name, description, now],
    )
    .map_err(map_unique(format!("project '{name}'")))?;
    get_project(conn, &id)
}

/// Look up a project by its (unique) name.
pub fn get_project_by_name(conn: &Connection, name: &str) -> Result<Option<Project>> {
    conn.query_row(
        "SELECT id, name, description, created_at, updated_at FROM projects WHERE name = ?1",
        [name.trim()],
        row_to_project,
    )
    .optional()
    .map_err(AppError::from)
}

pub fn list_projects(conn: &Connection) -> Result<Vec<Project>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, description, created_at, updated_at FROM projects ORDER BY name COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([], row_to_project)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn get_project(conn: &Connection, id: &str) -> Result<Project> {
    conn.query_row(
        "SELECT id, name, description, created_at, updated_at FROM projects WHERE id = ?1",
        [id],
        row_to_project,
    )
    .optional()?
    .ok_or_else(|| AppError::NotFound(format!("project {id}")))
}

pub fn update_project(
    conn: &Connection,
    id: &str,
    name: Option<&str>,
    description: Option<Option<&str>>,
) -> Result<Project> {
    let existing = get_project(conn, id)?;
    let new_name = match name {
        Some(n) => {
            let n = n.trim();
            if n.is_empty() {
                return Err(AppError::Invalid("project name must not be empty".into()));
            }
            n.to_string()
        }
        None => existing.name,
    };
    let new_desc = match description {
        Some(d) => d.map(|s| s.to_string()),
        None => existing.description,
    };
    conn.execute(
        "UPDATE projects SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
        params![new_name, new_desc, now_ms(), id],
    )
    .map_err(map_unique(format!("project '{new_name}'")))?;
    get_project(conn, id)
}

pub fn delete_project(conn: &Connection, id: &str) -> Result<()> {
    let n = conn.execute("DELETE FROM projects WHERE id = ?1", [id])?;
    if n == 0 {
        return Err(AppError::NotFound(format!("project {id}")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn add_secret(
    conn: &Connection,
    vault_key: &[u8; KEY_LEN],
    project_id: &str,
    key: &str,
    value: &str,
    description: Option<&str>,
    tags: &[String],
) -> Result<Secret> {
    let key = key.trim();
    if key.is_empty() {
        return Err(AppError::Invalid("secret key must not be empty".into()));
    }
    // Ensure the project exists (clearer error than a FK failure).
    get_project(conn, project_id)?;

    let id = new_id();
    let now = now_ms();
    let enc = crypto::encrypt(vault_key, value.as_bytes())?;
    conn.execute(
        "INSERT INTO secrets(id, project_id, key, value_encrypted, description, created_at, updated_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![id, project_id, key, enc, description, now],
    )
    .map_err(map_unique(format!("secret '{key}'")))?;

    set_tags(conn, &id, tags)?;
    get_secret(conn, vault_key, &id)
}

pub fn get_secret(conn: &Connection, vault_key: &[u8; KEY_LEN], id: &str) -> Result<Secret> {
    let row = conn
        .query_row(
            "SELECT id, project_id, key, value_encrypted, description, created_at, updated_at
             FROM secrets WHERE id = ?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("secret {id}")))?;

    let value = String::from_utf8(crypto::decrypt(vault_key, &row.3)?)
        .map_err(|_| AppError::crypto("decrypted value is not valid UTF-8"))?;
    let tags = tags_for_secret(conn, &row.0)?;

    Ok(Secret {
        id: row.0,
        project_id: row.1,
        key: row.2,
        value,
        description: row.4,
        tags,
        created_at: row.5,
        updated_at: row.6,
    })
}

/// Find a secret's id within a project by its key.
pub fn get_secret_id_by_key(
    conn: &Connection,
    project_id: &str,
    key: &str,
) -> Result<Option<String>> {
    conn.query_row(
        "SELECT id FROM secrets WHERE project_id = ?1 AND key = ?2",
        params![project_id, key.trim()],
        |r| r.get::<_, String>(0),
    )
    .optional()
    .map_err(AppError::from)
}

pub fn list_secrets(conn: &Connection, project_id: &str) -> Result<Vec<SecretMeta>> {
    let mut stmt = conn.prepare(
        "SELECT id, project_id, key, description, created_at, updated_at
         FROM secrets WHERE project_id = ?1 ORDER BY key COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([project_id], row_to_secret_meta)?;
    let mut out = Vec::new();
    for r in rows {
        let mut m = r?;
        m.tags = tags_for_secret(conn, &m.id)?;
        out.push(m);
    }
    Ok(out)
}

pub fn update_secret(
    conn: &Connection,
    vault_key: &[u8; KEY_LEN],
    id: &str,
    key: Option<&str>,
    value: Option<&str>,
    description: Option<Option<&str>>,
    tags: Option<&[String]>,
) -> Result<Secret> {
    let existing = get_secret(conn, vault_key, id)?;

    let new_key = match key {
        Some(k) => {
            let k = k.trim();
            if k.is_empty() {
                return Err(AppError::Invalid("secret key must not be empty".into()));
            }
            k.to_string()
        }
        None => existing.key,
    };
    let new_enc = match value {
        Some(v) => crypto::encrypt(vault_key, v.as_bytes())?,
        None => crypto::encrypt(vault_key, existing.value.as_bytes())?,
    };
    let new_desc = match description {
        Some(d) => d.map(|s| s.to_string()),
        None => existing.description,
    };

    conn.execute(
        "UPDATE secrets SET key = ?1, value_encrypted = ?2, description = ?3, updated_at = ?4
         WHERE id = ?5",
        params![new_key, new_enc, new_desc, now_ms(), id],
    )
    .map_err(map_unique(format!("secret '{new_key}'")))?;

    if let Some(t) = tags {
        set_tags(conn, id, t)?;
    }
    get_secret(conn, vault_key, id)
}

pub fn delete_secret(conn: &Connection, id: &str) -> Result<()> {
    let n = conn.execute("DELETE FROM secrets WHERE id = ?1", [id])?;
    if n == 0 {
        return Err(AppError::NotFound(format!("secret {id}")));
    }
    Ok(())
}

/// Search secret metadata by key/description substring, optionally scoped to a
/// project and/or requiring all of the given tags.
pub fn search_secrets(
    conn: &Connection,
    query: &str,
    project_id: Option<&str>,
    tags: Option<&[String]>,
) -> Result<Vec<SecretMeta>> {
    let like = format!("%{}%", query.trim());
    let mut sql = String::from(
        "SELECT id, project_id, key, description, created_at, updated_at
         FROM secrets WHERE (key LIKE ?1 OR IFNULL(description,'') LIKE ?1)",
    );
    let mut bind: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(like)];
    if let Some(pid) = project_id {
        sql.push_str(" AND project_id = ?2");
        bind.push(Box::new(pid.to_string()));
    }
    sql.push_str(" ORDER BY key COLLATE NOCASE");

    let mut stmt = conn.prepare(&sql)?;
    let params_ref: Vec<&dyn rusqlite::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(params_ref.as_slice(), row_to_secret_meta)?;

    let want_tags: Vec<String> = tags.map(|t| t.to_vec()).unwrap_or_default();
    let mut out = Vec::new();
    for r in rows {
        let mut m = r?;
        m.tags = tags_for_secret(conn, &m.id)?;
        if want_tags.iter().all(|wt| m.tags.contains(wt)) {
            out.push(m);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

pub fn list_tags(conn: &Connection) -> Result<Vec<Tag>> {
    let mut stmt = conn.prepare("SELECT id, name FROM tags ORDER BY name COLLATE NOCASE")?;
    let rows = stmt.query_map([], |r| Ok(Tag { id: r.get(0)?, name: r.get(1)? }))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn delete_tag(conn: &Connection, id: &str) -> Result<()> {
    let n = conn.execute("DELETE FROM tags WHERE id = ?1", [id])?;
    if n == 0 {
        return Err(AppError::NotFound(format!("tag {id}")));
    }
    Ok(())
}

/// Replace a secret's tag set. Creates tag rows as needed and prunes tags that
/// are no longer referenced by any secret.
fn set_tags(conn: &Connection, secret_id: &str, tags: &[String]) -> Result<()> {
    conn.execute("DELETE FROM secret_tags WHERE secret_id = ?1", [secret_id])?;
    for raw in tags {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        conn.execute("INSERT OR IGNORE INTO tags(id, name) VALUES(?1, ?2)", params![new_id(), name])?;
        let tag_id: String =
            conn.query_row("SELECT id FROM tags WHERE name = ?1", [name], |r| r.get(0))?;
        conn.execute(
            "INSERT OR IGNORE INTO secret_tags(secret_id, tag_id) VALUES(?1, ?2)",
            params![secret_id, tag_id],
        )?;
    }
    prune_orphan_tags(conn)?;
    Ok(())
}

fn prune_orphan_tags(conn: &Connection) -> Result<()> {
    conn.execute(
        "DELETE FROM tags WHERE id NOT IN (SELECT DISTINCT tag_id FROM secret_tags)",
        [],
    )?;
    Ok(())
}

fn tags_for_secret(conn: &Connection, secret_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT t.name FROM tags t
         JOIN secret_tags st ON st.tag_id = t.id
         WHERE st.secret_id = ?1 ORDER BY t.name COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([secret_id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

// ---------------------------------------------------------------------------
// Row mappers / helpers
// ---------------------------------------------------------------------------

fn row_to_project(r: &rusqlite::Row) -> rusqlite::Result<Project> {
    Ok(Project {
        id: r.get(0)?,
        name: r.get(1)?,
        description: r.get(2)?,
        created_at: r.get(3)?,
        updated_at: r.get(4)?,
    })
}

fn row_to_secret_meta(r: &rusqlite::Row) -> rusqlite::Result<SecretMeta> {
    Ok(SecretMeta {
        id: r.get(0)?,
        project_id: r.get(1)?,
        key: r.get(2)?,
        description: r.get(3)?,
        tags: Vec::new(),
        created_at: r.get(4)?,
        updated_at: r.get(5)?,
    })
}

/// Map a UNIQUE-constraint violation to a friendly `AlreadyExists` error.
fn map_unique(what: String) -> impl FnOnce(rusqlite::Error) -> AppError {
    move |e| match e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            AppError::AlreadyExists(what)
        }
        other => AppError::Database(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, vault};

    fn setup() -> (Connection, [u8; KEY_LEN]) {
        let (key, _sc, _codes) = vault::create("pw").unwrap();
        let conn = db::open_in_memory_keyed(&vault::key_hex(&key)).unwrap();
        (conn, key)
    }

    #[test]
    fn project_crud() {
        let (conn, _k) = setup();
        let p = create_project(&conn, "web", Some("frontend")).unwrap();
        assert_eq!(p.name, "web");
        assert_eq!(list_projects(&conn).unwrap().len(), 1);

        let up = update_project(&conn, &p.id, Some("web-app"), Some(None)).unwrap();
        assert_eq!(up.name, "web-app");
        assert_eq!(up.description, None);

        delete_project(&conn, &p.id).unwrap();
        assert!(list_projects(&conn).unwrap().is_empty());
    }

    #[test]
    fn duplicate_project_name_fails() {
        let (conn, _k) = setup();
        create_project(&conn, "dup", None).unwrap();
        assert!(matches!(create_project(&conn, "dup", None), Err(AppError::AlreadyExists(_))));
    }

    #[test]
    fn secret_crud_and_encryption() {
        let (conn, key) = setup();
        let p = create_project(&conn, "proj", None).unwrap();
        let s = add_secret(&conn, &key, &p.id, "DB_URL", "postgres://x", Some("prod db"), &["db".into(), "prod".into()]).unwrap();
        assert_eq!(s.value, "postgres://x");
        assert_eq!(s.tags, vec!["db".to_string(), "prod".to_string()]);

        // List omits value and includes tags.
        let list = list_secrets(&conn, &p.id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key, "DB_URL");
        assert_eq!(list[0].tags, vec!["db".to_string(), "prod".to_string()]);

        // Stored blob must not contain plaintext.
        let blob: Vec<u8> = conn
            .query_row("SELECT value_encrypted FROM secrets WHERE id=?1", [&s.id], |r| r.get(0))
            .unwrap();
        assert!(!blob.windows(11).any(|w| w == b"postgres://"));

        // Update value + tags.
        let u = update_secret(&conn, &key, &s.id, None, Some("postgres://y"), None, Some(&["db".into()])).unwrap();
        assert_eq!(u.value, "postgres://y");
        assert_eq!(u.tags, vec!["db".to_string()]);

        delete_secret(&conn, &s.id).unwrap();
        assert!(list_secrets(&conn, &p.id).unwrap().is_empty());
    }

    #[test]
    fn duplicate_secret_key_in_project_fails() {
        let (conn, key) = setup();
        let p = create_project(&conn, "proj", None).unwrap();
        add_secret(&conn, &key, &p.id, "K", "v", None, &[]).unwrap();
        assert!(matches!(
            add_secret(&conn, &key, &p.id, "K", "v2", None, &[]),
            Err(AppError::AlreadyExists(_))
        ));
    }

    #[test]
    fn deleting_project_cascades_secrets() {
        let (conn, key) = setup();
        let p = create_project(&conn, "proj", None).unwrap();
        let s = add_secret(&conn, &key, &p.id, "K", "v", None, &["t".into()]).unwrap();
        delete_project(&conn, &p.id).unwrap();
        assert!(matches!(get_secret(&conn, &key, &s.id), Err(AppError::NotFound(_))));
        // Orphan tag pruned when secret rows are gone (cascade leaves secret_tags empty).
        // (tags table cleaned on next set_tags; here just assert secret gone.)
    }

    #[test]
    fn search_by_key_and_tags() {
        let (conn, key) = setup();
        let p = create_project(&conn, "proj", None).unwrap();
        add_secret(&conn, &key, &p.id, "AWS_KEY", "a", None, &["aws".into(), "prod".into()]).unwrap();
        add_secret(&conn, &key, &p.id, "AWS_SECRET", "b", None, &["aws".into()]).unwrap();
        add_secret(&conn, &key, &p.id, "STRIPE", "c", None, &["api".into()]).unwrap();

        // Substring on key.
        let r = search_secrets(&conn, "AWS", None, None).unwrap();
        assert_eq!(r.len(), 2);

        // Tag filter requires all listed tags.
        let r = search_secrets(&conn, "", None, Some(&["aws".into(), "prod".into()])).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].key, "AWS_KEY");
    }

    #[test]
    fn list_tags_and_prune() {
        let (conn, key) = setup();
        let p = create_project(&conn, "proj", None).unwrap();
        let s = add_secret(&conn, &key, &p.id, "K", "v", None, &["x".into(), "y".into()]).unwrap();
        assert_eq!(list_tags(&conn).unwrap().len(), 2);
        // Removing a tag from the only secret prunes it.
        update_secret(&conn, &key, &s.id, None, None, None, Some(&["x".into()])).unwrap();
        let names: Vec<String> = list_tags(&conn).unwrap().into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["x".to_string()]);
    }

    #[test]
    fn get_missing_secret_errors() {
        let (conn, key) = setup();
        assert!(matches!(get_secret(&conn, &key, "nope"), Err(AppError::NotFound(_))));
    }
}
