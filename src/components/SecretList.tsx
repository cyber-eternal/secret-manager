// Center panel: searchable list of a project's secrets (values masked).

import { useMemo, useState } from "react";
import { Check, Copy, KeyRound, Plus, Search } from "lucide-react";
import { Badge, Button, IconButton, Input } from "./ui/controls";
import { getSecret } from "../lib/tauri";
import { copyWithAutoClear } from "../lib/clipboard";
import { useSettings } from "../store/settings";
import { cn, formatRelativeTime, maskValue } from "../lib/utils";
import type { Project, SecretMeta } from "../lib/types";

export function SecretList({
  project,
  secrets,
  selectedId,
  onSelect,
  onAdd,
}: {
  project: Project;
  secrets: SecretMeta[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onAdd: () => void;
}) {
  const clipboardClear = useSettings((s) => s.clipboardClearSeconds);
  const [query, setQuery] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return secrets;
    return secrets.filter(
      (s) =>
        s.key.toLowerCase().includes(q) ||
        (s.description ?? "").toLowerCase().includes(q) ||
        s.tags.some((t) => t.toLowerCase().includes(q)),
    );
  }, [secrets, query]);

  const copyRow = async (id: string) => {
    const full = await getSecret(id);
    await copyWithAutoClear(full.value, clipboardClear);
    setCopiedId(id);
    setTimeout(() => setCopiedId((c) => (c === id ? null : c)), 1500);
  };

  return (
    <section className="flex h-full min-w-0 flex-1 flex-col bg-bg">
      <div className="border-b border-border-subtle px-6 pt-5 pb-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-[20px] font-semibold tracking-tight text-text">
              {project.name}
            </h1>
            {project.description && (
              <p className="mt-0.5 text-[12.5px] text-text-muted">
                {project.description}
              </p>
            )}
          </div>
          <Button size="sm" onClick={onAdd}>
            <Plus className="h-4 w-4" /> Add secret
          </Button>
        </div>

        <div className="relative mt-4">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-dim" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter secrets…"
            className="pl-9"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 ? (
          <EmptyState hasAny={secrets.length > 0} onAdd={onAdd} />
        ) : (
          <ul>
            {filtered.map((s) => (
              <li key={s.id}>
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => onSelect(s.id)}
                  onKeyDown={(e) => e.key === "Enter" && onSelect(s.id)}
                  className={cn(
                    "group grid h-[62px] cursor-pointer grid-cols-[1fr_200px_96px_36px] items-center gap-3 border-b border-border-subtle px-6 transition-colors",
                    s.id === selectedId
                      ? "bg-accent-soft"
                      : "hover:bg-surface",
                    s.id === selectedId &&
                      "border-l-[2.5px] border-l-accent pl-[21.5px]",
                  )}
                >
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[13px] text-text">
                      {s.key}
                    </div>
                    <div className="truncate font-mono text-[12px] text-text-dim">
                      {maskValue()}
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1 overflow-hidden">
                    {s.tags.slice(0, 3).map((t) => (
                      <Badge key={t}>{t}</Badge>
                    ))}
                  </div>
                  <div className="text-[11.5px] text-text-dim">
                    {formatRelativeTime(s.updated_at)}
                  </div>
                  <div onClick={(e) => e.stopPropagation()}>
                    <IconButton
                      label="Copy value"
                      onClick={() => copyRow(s.id)}
                      className="opacity-0 group-hover:opacity-100"
                    >
                      {copiedId === s.id ? (
                        <Check className="h-4 w-4 text-[color:var(--success)]" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </IconButton>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function EmptyState({ hasAny, onAdd }: { hasAny: boolean; onAdd: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-dashed border-border text-text-dim">
        <KeyRound className="h-7 w-7" />
      </div>
      <div>
        <p className="text-[14px] font-medium text-text">
          {hasAny ? "No matches" : "No secrets yet"}
        </p>
        <p className="mt-1 text-[12.5px] text-text-muted">
          {hasAny
            ? "Try a different search."
            : "Add your first secret to this project."}
        </p>
      </div>
      {!hasAny && (
        <Button size="sm" onClick={onAdd}>
          <Plus className="h-4 w-4" /> Add secret
        </Button>
      )}
    </div>
  );
}
