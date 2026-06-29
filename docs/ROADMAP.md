# Roadmap

## Phase 1 — Core (Personal Use)

Goal: working desktop app. Unlock vault, manage projects and secrets, search.

### Milestone 1.1 — Rust Core
- [ ] Scaffold Tauri project (`cargo tauri init`)
- [ ] `crypto.rs`: Argon2id key derivation, AES-256-GCM encrypt/decrypt
- [ ] `db.rs`: SQLite init, migration runner, connection pool
- [ ] `vault.rs`: create vault, unlock, lock, change password
- [ ] `models.rs`: Project, Secret, Tag structs with serde
- [ ] Unit tests: crypto round-trip, DB CRUD, vault unlock/lock cycle

### Milestone 1.2 — Tauri Commands
- [ ] Vault commands: `create_vault`, `unlock_vault`, `lock_vault`, `vault_is_unlocked`, `change_master_password`
- [ ] Project commands: `create_project`, `list_projects`, `get_project`, `update_project`, `delete_project`
- [ ] Secret commands: `add_secret`, `get_secret`, `list_secrets`, `update_secret`, `delete_secret`
- [ ] Search command: `search_secrets` (by key name, description, tags)
- [ ] Tag management: `list_tags`, `delete_tag`

### Milestone 1.3 — Frontend Foundation
- [ ] Scaffold React + TypeScript + Vite frontend
- [ ] Configure Tailwind CSS + shadcn/ui
- [ ] Typed `invoke()` wrappers in `src/lib/tauri.ts`
- [ ] Zustand vault store
- [ ] React Router setup

### Milestone 1.4 — UI: Core Screens
- [ ] UnlockScreen: master password entry, first-run vault creation flow
- [ ] Sidebar: project list, create project
- [ ] SecretList: table of secrets for active project (keys visible, values masked)
- [ ] SecretDetail: view/edit/delete a secret, reveal value toggle
- [ ] AddSecret form: key, value, description, tags
- [ ] Search bar: live search across key names and tags
- [ ] Settings: change master password, vault file path

### Milestone 1.5 — Polish & Distribution
- [ ] App icon (all platforms)
- [ ] Auto-lock after inactivity (configurable timeout)
- [ ] Clipboard copy with auto-clear (30s)
- [ ] Tauri updater setup
- [ ] Build pipeline: GitHub Actions → artifacts for macOS, Windows, Linux

**Acceptance criteria for Phase 1:** A user can install the app, create a vault, add projects with secrets, search, and retrieve values. Data survives app restart. Vault requires password on every app open.

---

## Phase 2 — UX & Power Features

Goal: app feels polished and production-ready for daily use.

Delivered ahead of plan:
- [x] Global search across all projects (⌘K command palette: projects + secrets)
- [x] Master-password recovery via single-use recovery codes
- [x] Export all data / single project to JSON; import with skip/overwrite
- [x] Dark mode / light mode / system toggle
- [x] Show-password toggles; buttons lock + show a spinner during async actions

Still planned:
- [ ] Keyboard shortcuts beyond ⌘K (Cmd/Ctrl+C copy, etc.)
- [ ] Bulk import from `.env` files / export project to `.env` (password-gated)
- [ ] Encrypted backup file format (export is currently plaintext JSON)
- [ ] Secret history (keep last N versions on update)
- [ ] Duplicate secret / duplicate project
- [ ] Drag-and-drop secret reordering
- [ ] Multiple vaults (open different vault files)
- [ ] Onboarding tutorial for first-time users

---

## Phase 3 — Team Sharing

Goal: small team (2–10 people) can share secrets across projects with role-based access.

### Milestone 3.1 — Self-hosted Server
- [ ] Simple REST API (Go or Rust, TBD)
- [ ] Endpoints: auth (JWT), projects, secrets (ciphertext only), members, sync
- [ ] Docker Compose deployment
- [ ] Server stores only ciphertext — no plaintext ever

### Milestone 3.2 — Client Sync
- [ ] Sync configuration in Settings: server URL + API key
- [ ] Background sync daemon (Tauri async task)
- [ ] Conflict resolution: last-write-wins per secret, with version vector
- [ ] Sync status indicator in UI

### Milestone 3.3 — Access Control
- [ ] User identity: public/private key pair generated on first server connect
- [ ] Project roles: `admin` (CRUD) and `reader` (view/search only)
- [ ] Envelope encryption: project key encrypted per member with their public key
- [ ] Admin UI: invite user to project, change role, revoke access
- [ ] Reader UI: read-only view (no edit/delete controls)

### Milestone 3.4 — Audit
- [ ] Audit log: who accessed which secret, when
- [ ] Server-side audit trail
- [ ] Export audit log as CSV

**Acceptance criteria for Phase 3:** Admin installs server, invites team members by username, assigns project access. Members sync and read secrets without ever receiving the vault key. Admin can revoke access.
