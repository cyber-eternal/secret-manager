# secret-manager — UI Design

`Secret Manager UI.dc.html` is a pannable canvas of high-fidelity mockups. Open it in the browser and pan/zoom to see every screen. This README is the implementation spec for the Tauri + React + Tailwind + shadcn/ui frontend.

## Frames included
- **Unlock** — Direction A (minimal centered), Direction B (split brand panel), first-run "Create vault", and a light variant
- **Main app** — three-panel vault with a secret selected (dark + light)
- **Command palette** — ⌘K full-text search overlay
- **Add secret** — modal dialog
- **Settings** — Security / Vault / Appearance (dark + light)
- **States** — empty project + destructive delete confirm

Decision: **Direction A** is the committed unlock layout (B kept for reference).

## Design tokens

### Dark (primary)
| Token | Hex |
|---|---|
| `bg` (app) | `#0f1117` |
| `bg-titlebar` | `#0b0d12` |
| `panel` (sidebar / detail) | `#0c0e13` |
| `surface` (cards, inputs) | `#14171e` |
| `surface-raised` (modals) | `#15181f` |
| `border` | `#2a2d35` |
| `border-subtle` | `#1c1f27` / `#15181f` |
| `text` | `#e2e8f0` |
| `text-secondary` | `#cbd5e1` |
| `text-muted` | `#64748b` |
| `text-dim` | `#475569` |
| `accent` | `#3b82f6` |
| `accent-fg` (on dark surface) | `#60a5fa` / `#93c5fd` |
| `accent-soft` | `rgba(59,130,246,0.12)` |
| `danger` | `#ef4444` |
| `danger-soft` | `rgba(239,68,68,0.10)` |
| `success` | `#22c55e` |

### Light
| Token | Hex |
|---|---|
| `bg` | `#f8fafc` |
| `surface` | `#ffffff` |
| `sidebar` | `#f8fafc` / titlebar `#f1f5f9` |
| `border` | `#e2e8f0` |
| `border-subtle` | `#eef2f6` |
| `text` | `#0f172a` |
| `text-secondary` | `#334155` |
| `text-muted` | `#64748b` |
| `text-dim` | `#94a3b8` |
| `accent` | `#2563eb` (darker for AA contrast) |

### Tag colors (subtle pill `bg = color @ ~14% alpha`)
- `prod` — amber `#fbbf24` (dark) / `#b45309` (light)
- `api` — blue `#93c5fd` / `#1d4ed8`
- `db` — teal `#5eead4` / `#0f766e`
- neutral (`aws`, `monitoring`) — slate `#cbd5e1` / `#475569`

## Type
- **UI / sans:** Geist — weights 400/500/600/700
- **Keys, values, paths, timestamps, kbd:** Fira Code — weights 400/500/600
- Section labels: 10.5px, 600, uppercase, `letter-spacing .6–.8px`, muted
- Body 13–14px; page titles 19–22px; inputs 13.5–14px

## Layout
- Sidebar **240px**, detail panel **360px**, center flex
- Comfortable rows: **62px**, two-line cell (key + masked value)
- List grid: `1fr 200px 96px 36px` (key / tags / updated / copy)
- Radius: cards 12–14px, inputs/buttons 8–10px, pills 5–6px
- Window chrome: 38px titlebar with macOS traffic-light dots

## Components (map to shadcn/ui)
- `Input` — 40–48px, 1px border, focus = accent border + `0 0 0 3px accent@18%` ring
- `Button` primary — accent bg, `box-shadow: 0 6px 16px -8px accent@70%`
- `Badge` — tag pills, removable with `×`
- `Dialog` — Add secret, delete confirm; overlay `rgba(7,9,13,0.7)`
- `Command` (cmdk) — ⌘K palette; active row = `accent@14%` + 2.5px left accent bar
- `Tooltip`, `Select` (chevron-down), segmented control for theme toggle
- Icons: **lucide-react** (matches the icon set used here)

## Interaction states shown
- **Focus** — accent border + ring (unlock field, Add-secret key field)
- **Hover row** — `surface` bg + copy button becomes a bordered accent button
- **Selected row** — `accent-soft` bg + 2.5px left accent bar
- **Copy confirmed** — checkmark + "Copied" for ~1.5s, then clipboard auto-clears (default 30s)
- **Value reveal** — masked `••••` by default; eye toggle in detail panel / modal
- **Empty state** — dashed vault glyph + "Add your first secret" CTA + import-from-.env
- **Destructive** — type-to-confirm; primary button disabled until project name matches

## Notes
- Secret values are never rendered in the list — only masked dots. Plaintext appears only in the detail panel after an explicit reveal, and is cleared from React state on navigation (per ARCHITECTURE.md).
- The mockup loads Lucide from a CDN for convenience; the real app uses `lucide-react`.
