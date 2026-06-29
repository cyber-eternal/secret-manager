// Dialogs for export (choose format + passphrase) and import (auto-detect
// encrypted files and prompt for a passphrase).

import { useState } from "react";
import { FileJson, Lock, ShieldAlert, Upload } from "lucide-react";
import { Button, PasswordInput } from "./ui/controls";
import { Dialog } from "./ui/Dialog";
import { cn, errMessage } from "../lib/utils";
import {
  pickImportFile,
  runImport,
  summarizeImport,
  type ExportOptions,
} from "../lib/transfer";
import type { ImportMode, ImportSummary } from "../lib/types";

/** Choose JSON vs encrypted vault file, then run the supplied export. */
export function ExportOptionsDialog({
  open,
  title,
  onClose,
  doExport,
  onExported,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  doExport: (opts: ExportOptions) => Promise<string | null>;
  onExported?: (path: string) => void;
}) {
  const [encrypted, setEncrypted] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    if (busy) return;
    setEncrypted(false);
    setPassphrase("");
    setError(null);
    onClose();
  };

  const submit = async () => {
    setError(null);
    if (encrypted && passphrase.length < 6) {
      setError("Passphrase must be at least 6 characters.");
      return;
    }
    setBusy(true);
    try {
      const path = await doExport({ encrypted, passphrase: encrypted ? passphrase : undefined });
      if (path && onExported) onExported(path);
      setBusy(false);
      close();
    } catch (e) {
      setError(errMessage(e));
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title={title}>
      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-2">
          <FormatCard
            active={!encrypted}
            onClick={() => setEncrypted(false)}
            icon={<FileJson className="h-4 w-4" />}
            label="JSON"
            note="Plaintext values"
          />
          <FormatCard
            active={encrypted}
            onClick={() => setEncrypted(true)}
            icon={<Lock className="h-4 w-4" />}
            label="Vault file"
            note="Encrypted (.smvault)"
          />
        </div>

        {encrypted ? (
          <div>
            <label className="section-label mb-1.5 block">Passphrase</label>
            <PasswordInput
              autoFocus
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Used to encrypt the file"
              className="font-mono"
            />
            <p className="mt-2 text-[11.5px] text-text-dim">
              You'll need this passphrase to import the file later. It is not
              recoverable.
            </p>
          </div>
        ) : (
          <div className="flex items-start gap-2 rounded-lg border border-[color:var(--danger)]/30 bg-danger-soft px-3 py-2.5 text-[12px] text-text-secondary">
            <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
            <p>This file holds your secret values in plaintext. Store it securely.</p>
          </div>
        )}

        {error && <p className="text-[12.5px] text-danger">{error}</p>}

        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} loading={busy}>
            Export
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

function FormatCard({
  active,
  onClick,
  icon,
  label,
  note,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
  note: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex flex-col items-start gap-1 rounded-lg border p-3 text-left transition-colors",
        active
          ? "border-accent bg-accent-soft"
          : "border-border hover:bg-surface",
      )}
    >
      <span className="flex items-center gap-1.5 text-[13px] font-medium text-text">
        {icon}
        {label}
      </span>
      <span className="text-[11px] text-text-muted">{note}</span>
    </button>
  );
}

/** Pick a file, prompt for a passphrase if it's encrypted, then import. */
export function ImportDialog({
  open,
  onClose,
  onImported,
}: {
  open: boolean;
  onClose: () => void;
  onImported: (summary: ImportSummary) => void;
}) {
  const [mode, setMode] = useState<ImportMode>("skip");
  const [picked, setPicked] = useState<{ path: string; encrypted: boolean } | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setMode("skip");
    setPicked(null);
    setPassphrase("");
    setError(null);
  };
  const close = () => {
    if (busy) return;
    reset();
    onClose();
  };

  const choose = async () => {
    setError(null);
    try {
      const p = await pickImportFile();
      if (p) setPicked(p);
    } catch (e) {
      setError(errMessage(e));
    }
  };

  const submit = async () => {
    if (!picked) return;
    setError(null);
    if (picked.encrypted && passphrase.length === 0) {
      setError("This file is encrypted — enter its passphrase.");
      return;
    }
    setBusy(true);
    try {
      const summary = await runImport(
        picked.path,
        mode,
        picked.encrypted ? passphrase : undefined,
      );
      setBusy(false);
      reset();
      onImported(summary);
      onClose();
    } catch (e) {
      setError(errMessage(e));
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={close} title="Import">
      <div className="space-y-4">
        <div>
          <label className="section-label mb-1.5 block">File</label>
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={choose} disabled={busy}>
              <Upload className="h-4 w-4" /> Choose file…
            </Button>
            {picked && (
              <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-text-muted">
                {picked.path.split(/[/\\]/).pop()}
                {picked.encrypted && (
                  <span className="ml-1.5 text-accent-fg">· encrypted</span>
                )}
              </span>
            )}
          </div>
        </div>

        {picked?.encrypted && (
          <div>
            <label className="section-label mb-1.5 block">Passphrase</label>
            <PasswordInput
              autoFocus
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Passphrase used at export"
              className="font-mono"
            />
          </div>
        )}

        <div>
          <label className="section-label mb-1.5 block">On duplicate key</label>
          <div className="flex gap-1.5">
            {(["skip", "overwrite"] as ImportMode[]).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className={cn(
                  "rounded-lg border px-3 py-1.5 text-[12.5px] capitalize transition-colors",
                  mode === m
                    ? "border-accent bg-accent-soft text-text"
                    : "border-border text-text-muted hover:text-text",
                )}
              >
                {m}
              </button>
            ))}
          </div>
        </div>

        {error && <p className="text-[12.5px] text-danger">{error}</p>}

        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} loading={busy} disabled={!picked}>
            Import
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

export { summarizeImport };
