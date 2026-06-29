# UI Design Prompt

Use this prompt with Claude or any AI design tool to generate UI designs for the secret-manager app.

---

## Prompt

Design a desktop application UI for **secret-manager** — a cross-platform (macOS, Windows, Linux) app for securely storing environment variables and secrets. Built with Tauri (native webview), React, and Tailwind CSS + shadcn/ui components.

### App Purpose
Users store secrets (API keys, passwords, DB credentials, env vars) organized by projects. The vault is protected by a master password. Think: 1Password or KeePass but purpose-built for developers managing `.env` files and project secrets.

### Design Principles
- **Security-first feel**: the UI should communicate safety and trust. Dark, minimal, no clutter.
- **Developer aesthetic**: monospace font for keys/values, terminal-inspired color accents (not toy-colorful — think VS Code or Linear).
- **Efficiency**: power users. Keyboard-first. Everything reachable without a mouse.
- **Calm**: no bright marketing colors. Neutral dark background, subtle borders, muted text hierarchy.

### Color Direction
- Background: very dark neutral (not pure black — e.g. `#0f1117` or `#111318`)
- Surface/cards: slightly lighter (`#1a1d25`)
- Border: subtle (`#2a2d35`)
- Primary accent: cool blue or teal (`#3b82f6` or `#14b8a6`)
- Danger: muted red (`#ef4444`)
- Text primary: `#e2e8f0`
- Text muted: `#64748b`
- Monospace font for keys/values: JetBrains Mono, Fira Code, or similar

### Screens to Design

#### 1. Unlock Screen
- Full-screen centered layout
- App logo/icon (lockbox or key motif — simple, geometric)
- "Enter master password" label + password input field
- Unlock button
- "Create new vault" link for first-time users
- Subtle background texture or gradient — not flat black
- First-run variant: shows "Create vault" form with password + confirm password

#### 2. Main App Layout
Three-panel layout:
- **Left panel (240px)**: project list sidebar
  - App logo/name at top
  - List of projects (icon + name)
  - Active project highlighted
  - "+ New Project" button at bottom
  - Settings gear icon at very bottom
- **Center panel (flex)**: secret list for active project
  - Project name as header
  - Search bar at top (Cmd+K shortcut hint)
  - Table/list of secrets: key name | tags | last updated | copy button
  - Secret values are hidden by default (masked with ••••••••)
  - "+ Add Secret" button
- **Right panel (360px)**: secret detail / edit (slides in when secret selected)
  - Secret key (editable, monospace)
  - Secret value (editable, monospace, toggle visibility)
  - Description (optional textarea)
  - Tags (pill input)
  - Created/Updated timestamps
  - Delete button (danger, bottom)

#### 3. Add / Edit Secret Modal or Inline Panel
- Key field (monospace, autofocus)
- Value field (monospace, password-type with reveal toggle)
- Description (textarea, optional)
- Tags input (type and press Enter to add, removable pills)
- Save / Cancel buttons

#### 4. Search
- Full-text search overlay (Cmd+K) — similar to Raycast or Linear command palette
- Searches across: key names, descriptions, tags
- Results show: key name, project name, tags
- Keyboard navigable (arrow keys + Enter)

#### 5. Settings Screen
- Change master password (old → new → confirm)
- Vault file path (current path + "Browse" button to change)
- Auto-lock timeout (dropdown: 1 min, 5 min, 15 min, never)
- Clipboard clear timeout (default 30s)
- Theme toggle (dark / light / system)

### Component Notes
- Use shadcn/ui primitives: Dialog, Input, Button, Badge (for tags), Table, Tooltip
- Secret value reveal: eye icon toggle, value blurred until clicked
- Copy button: icon only, shows checkmark for 1.5s after copy
- Tag pills: colored, subtle background, × to remove
- Destructive actions require confirmation (e.g. delete project warns "this will delete N secrets")
- Empty states: friendly illustration + CTA (e.g. "No secrets yet — add your first one")

### Interaction Details
- Vault auto-locks after configurable inactivity timeout
- Locked state shows the Unlock Screen over the app (overlay, not navigation)
- Secret values never shown in the list view — only in the detail panel after click
- Clipboard copy auto-clears after 30 seconds (configurable)

### Deliverable
Provide high-fidelity mockups for: Unlock Screen, Main App (with secret selected), Search overlay, Add Secret form, and Settings screen. Include both dark mode (primary) and light mode variants if possible. Annotate key interaction states (hover, focus, active, empty state).
