// ⌘K / Ctrl+K global search across all projects — matches both project names
// and secrets (key / description / tags).

import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CornerDownLeft, Folder, KeyRound, Search } from "lucide-react";
import { Badge } from "./ui/controls";
import { searchSecrets } from "../lib/tauri";
import { useVault } from "../store/vault";
import { useUI } from "../store/ui";
import { cn, errMessage } from "../lib/utils";
import type { Project, SecretMeta } from "../lib/types";

type Item =
  | { type: "project"; project: Project }
  | { type: "secret"; secret: SecretMeta };

export function CommandPalette() {
  const navigate = useNavigate();
  const projects = useVault((s) => s.projects);
  const isUnlocked = useVault((s) => s.isUnlocked);
  const open = useUI((s) => s.paletteOpen);
  const closePalette = useUI((s) => s.closePalette);

  const [query, setQuery] = useState("");
  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [active, setActive] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const projectName = useMemo(() => {
    const m = new Map<string, string>();
    projects.forEach((p) => m.set(p.id, p.name));
    return m;
  }, [projects]);

  // Combined, ordered result list: matching projects first, then secrets.
  const items: Item[] = useMemo(() => {
    const q = query.trim().toLowerCase();
    const projHits = q
      ? projects.filter(
          (p) =>
            p.name.toLowerCase().includes(q) ||
            (p.description ?? "").toLowerCase().includes(q),
        )
      : [];
    return [
      ...projHits.map((project): Item => ({ type: "project", project })),
      ...secrets.map((secret): Item => ({ type: "secret", secret })),
    ];
  }, [projects, secrets, query]);

  // Global ⌘K / Ctrl+K toggle.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (isUnlocked) useUI.getState().togglePalette();
      } else if (e.key === "Escape") {
        closePalette();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isUnlocked, closePalette]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSecrets([]);
      setActive(0);
      setError(null);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  // Debounced secret search across all projects.
  useEffect(() => {
    if (!open) return;
    const handle = setTimeout(async () => {
      try {
        const r = await searchSecrets(query);
        setSecrets(r);
        setActive(0);
      } catch (e) {
        setError(errMessage(e));
      }
    }, 120);
    return () => clearTimeout(handle);
  }, [query, open]);

  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(0, items.length - 1)));
  }, [items.length]);

  const choose = (item: Item) => {
    closePalette();
    if (item.type === "project") {
      navigate(`/projects/${item.project.id}`);
    } else {
      navigate(`/projects/${item.secret.project_id}`, {
        state: { selectSecretId: item.secret.id },
      });
    }
  };

  if (!open) return null;

  return (
    <div
      role="presentation"
      onMouseDown={(e) => e.target === e.currentTarget && closePalette()}
      className="fixed inset-0 z-[60] flex items-start justify-center bg-[rgba(7,9,13,0.7)] p-4 pt-[14vh]"
    >
      <div className="w-full max-w-xl overflow-hidden rounded-2xl border border-border bg-surface-raised shadow-2xl">
        <div className="flex items-center gap-3 border-b border-border-subtle px-4">
          <Search className="h-4 w-4 text-text-dim" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                setActive((a) => Math.min(a + 1, items.length - 1));
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                setActive((a) => Math.max(a - 1, 0));
              } else if (e.key === "Enter" && items[active]) {
                choose(items[active]);
              }
            }}
            placeholder="Search projects and secrets…"
            className="h-12 flex-1 bg-transparent text-[14px] text-text outline-none placeholder:text-text-dim"
          />
          <kbd className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-text-dim">
            ESC
          </kbd>
        </div>

        <ul className="max-h-80 overflow-y-auto py-1">
          {error && <li className="px-4 py-3 text-[12.5px] text-danger">{error}</li>}
          {!error && items.length === 0 && (
            <li className="px-4 py-6 text-center text-[12.5px] text-text-dim">
              {query ? "No matching projects or secrets." : "Type to search."}
            </li>
          )}
          {items.map((item, i) => {
            const isProject = item.type === "project";
            const id = isProject ? item.project.id : item.secret.id;
            const title = isProject ? item.project.name : item.secret.key;
            const subtitle = isProject
              ? "Project"
              : (projectName.get(item.secret.project_id) ?? "—");
            const tags = isProject ? [] : item.secret.tags;
            return (
              <li key={`${item.type}-${id}`}>
                <button
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(item)}
                  className={cn(
                    "flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left",
                    i === active && "bg-accent-soft border-l-[2.5px] border-l-accent pl-[13.5px]",
                  )}
                >
                  <div className="flex min-w-0 items-center gap-2.5">
                    {isProject ? (
                      <Folder className="h-4 w-4 shrink-0 text-accent-fg" />
                    ) : (
                      <KeyRound className="h-4 w-4 shrink-0 text-text-muted" />
                    )}
                    <div className="min-w-0">
                      <div className="truncate font-mono text-[13px] text-text">
                        {title}
                      </div>
                      <div className="truncate text-[11.5px] text-text-muted">
                        {subtitle}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {tags.slice(0, 2).map((t) => (
                      <Badge key={t}>{t}</Badge>
                    ))}
                    {i === active && (
                      <CornerDownLeft className="h-3.5 w-3.5 text-text-dim" />
                    )}
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
