// Left navigation: project list + create, settings, lock.

import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Download,
  Folder,
  Lock,
  Plus,
  Search,
  Settings as SettingsIcon,
  ShieldCheck,
  Upload,
} from "lucide-react";
import { useVault } from "../store/vault";
import { useUI } from "../store/ui";
import { Button, IconButton, Input, Textarea } from "./ui/controls";
import { Dialog } from "./ui/Dialog";
import { exportProjectFlow } from "../lib/transfer";
import {
  ExportOptionsDialog,
  ImportDialog,
  summarizeImport,
} from "./TransferDialogs";
import { cn, errMessage } from "../lib/utils";

export function Sidebar() {
  const navigate = useNavigate();
  const { id: activeId } = useParams();
  const { projects, createProject, lock, refreshProjects } = useVault();
  const openPalette = useUI((s) => s.openPalette);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [importOpen, setImportOpen] = useState(false);
  const [exportTarget, setExportTarget] = useState<{ id: string; name: string } | null>(null);
  const [flash, setFlash] = useState<{ ok: boolean; text: string } | null>(null);
  const [menu, setMenu] = useState<{ id: string; name: string; x: number; y: number } | null>(null);

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    window.addEventListener("click", close);
    window.addEventListener("contextmenu", close);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("contextmenu", close);
    };
  }, [menu]);

  useEffect(() => {
    if (!flash) return;
    const t = setTimeout(() => setFlash(null), 4000);
    return () => clearTimeout(t);
  }, [flash]);

  const openExport = (id: string, pname: string) => {
    setMenu(null);
    setFlash(null);
    setExportTarget({ id, name: pname });
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const p = await createProject(name.trim(), desc.trim() || undefined);
      setOpen(false);
      setName("");
      setDesc("");
      navigate(`/projects/${p.id}`);
    } catch (err) {
      setError(errMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <aside className="flex h-full w-60 flex-col border-r border-border bg-panel">
      <div className="flex items-center gap-2 px-4 py-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent-soft text-accent-fg">
          <ShieldCheck className="h-4 w-4" />
        </div>
        <span className="text-[14px] font-semibold tracking-tight text-text">
          secret-manager
        </span>
      </div>

      <div className="px-3 pb-3">
        <button
          onClick={openPalette}
          className="flex w-full items-center gap-2 rounded-lg border border-border bg-surface px-2.5 py-2 text-left text-[12.5px] text-text-muted transition-colors hover:text-text"
        >
          <Search className="h-4 w-4 text-text-dim" />
          <span className="flex-1">Search all projects…</span>
          <kbd className="rounded border border-border px-1 py-0.5 font-mono text-[10px] text-text-dim">
            ⌘K
          </kbd>
        </button>
      </div>

      <div className="px-3 pb-1">
        <span className="section-label px-1">Projects</span>
      </div>

      <nav className="flex-1 overflow-y-auto px-2">
        {projects.length === 0 && (
          <p className="px-2 py-3 text-[12.5px] text-text-dim">No projects yet.</p>
        )}
        {projects.map((p) => (
          <button
            key={p.id}
            onClick={() => navigate(`/projects/${p.id}`)}
            onContextMenu={(e) => {
              e.preventDefault();
              setMenu({ id: p.id, name: p.name, x: e.clientX, y: e.clientY });
            }}
            className={cn(
              "mb-0.5 flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-[13px] transition-colors",
              p.id === activeId
                ? "bg-accent-soft text-text"
                : "text-text-secondary hover:bg-surface hover:text-text",
            )}
          >
            <Folder
              className={cn(
                "h-4 w-4 shrink-0",
                p.id === activeId ? "text-accent-fg" : "text-text-muted",
              )}
            />
            <span className="truncate">{p.name}</span>
          </button>
        ))}
      </nav>

      <div className="space-y-1 border-t border-border-subtle p-2">
        {flash && (
          <p
            className={cn(
              "px-1 pb-1 text-[11.5px]",
              flash.ok ? "text-[color:var(--success)]" : "text-danger",
            )}
          >
            {flash.text}
          </p>
        )}
        <div className="flex gap-1.5">
          <Button
            variant="secondary"
            size="sm"
            className="flex-1"
            onClick={() => setOpen(true)}
          >
            <Plus className="h-4 w-4" /> New
          </Button>
          <Button
            variant="secondary"
            size="sm"
            className="flex-1"
            onClick={() => {
              setFlash(null);
              setImportOpen(true);
            }}
          >
            <Upload className="h-4 w-4" /> Import
          </Button>
        </div>
        <div className="flex items-center justify-between px-1 pt-1">
          <IconButton label="Settings" onClick={() => navigate("/settings")}>
            <SettingsIcon className="h-4 w-4" />
          </IconButton>
          <IconButton label="Lock vault" onClick={() => lock()}>
            <Lock className="h-4 w-4" />
          </IconButton>
        </div>
      </div>

      {menu && (
        <div
          className="fixed z-[70] min-w-40 overflow-hidden rounded-lg border border-border bg-surface-raised py-1 shadow-2xl"
          style={{ top: menu.y, left: menu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => openExport(menu.id, menu.name)}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-[12.5px] text-text-secondary hover:bg-surface hover:text-text"
          >
            <Download className="h-4 w-4" /> Export project
          </button>
        </div>
      )}

      <ImportDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={async (summary) => {
          await refreshProjects();
          setFlash({ ok: true, text: `Imported: ${summarizeImport(summary)}` });
        }}
      />

      {exportTarget && (
        <ExportOptionsDialog
          open
          title={`Export "${exportTarget.name}"`}
          onClose={() => setExportTarget(null)}
          doExport={(opts) =>
            exportProjectFlow(exportTarget.id, exportTarget.name, opts)
          }
          onExported={() => setFlash({ ok: true, text: `Exported "${exportTarget.name}".` })}
        />
      )}

      <Dialog open={open} onClose={() => setOpen(false)} title="New project">
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="section-label mb-1.5 block">Name</label>
            <Input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. web-app"
            />
          </div>
          <div>
            <label className="section-label mb-1.5 block">Description (optional)</label>
            <Textarea
              rows={2}
              value={desc}
              onChange={(e) => setDesc(e.target.value)}
              placeholder="What is this project for?"
            />
          </div>
          {error && <p className="text-[12.5px] text-danger">{error}</p>}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" loading={busy} disabled={!name.trim()}>
              Create
            </Button>
          </div>
        </form>
      </Dialog>
    </aside>
  );
}
