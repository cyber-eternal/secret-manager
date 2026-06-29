// Settings: security (change password), vault path, auto-lock, clipboard, theme.

import { useEffect, useState, type FormEvent } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { Download, FolderOpen, KeyRound, Upload } from "lucide-react";
import { Button, Input, PasswordInput } from "../components/ui/controls";
import { Dialog } from "../components/ui/Dialog";
import { RecoveryCodes } from "../components/RecoveryCodes";
import {
  changeMasterPassword,
  getVaultPath,
  regenerateRecoveryCodes,
} from "../lib/tauri";
import { exportAllFlow } from "../lib/transfer";
import {
  ExportOptionsDialog,
  ImportDialog,
  summarizeImport,
} from "../components/TransferDialogs";
import { useSettings, applyTheme, type AutoLockMinutes } from "../store/settings";
import { useVault } from "../store/vault";
import type { ThemePref } from "../lib/types";
import {
  cn,
  errMessage,
  validateMasterPassword,
} from "../lib/utils";

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-border bg-surface p-5">
      <h2 className="mb-4 text-[14px] font-semibold text-text">{title}</h2>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

export function Settings() {
  const settings = useSettings();
  const refreshProjects = useVault((s) => s.refreshProjects);
  const [vaultPath, setVaultPath] = useState<string | null>(null);

  // export / import
  const [exportOpen, setExportOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [transferMsg, setTransferMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // change-password form
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwMsg, setPwMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // recovery codes
  const [newCodes, setNewCodes] = useState<string[] | null>(null);
  const [codesBusy, setCodesBusy] = useState(false);
  const [codesErr, setCodesErr] = useState<string | null>(null);

  useEffect(() => {
    getVaultPath().then(setVaultPath).catch(() => setVaultPath(null));
  }, []);

  const submitPw = async (e: FormEvent) => {
    e.preventDefault();
    setPwMsg(null);
    const check = validateMasterPassword(newPw, confirmPw);
    if (!check.ok) {
      setPwMsg({ ok: false, text: check.message ?? "Invalid password" });
      return;
    }
    setPwBusy(true);
    try {
      await changeMasterPassword(oldPw, newPw);
      setPwMsg({ ok: true, text: "Master password changed. Secrets re-encrypted." });
      setOldPw("");
      setNewPw("");
      setConfirmPw("");
    } catch (err) {
      setPwMsg({ ok: false, text: errMessage(err) });
    } finally {
      setPwBusy(false);
    }
  };

  const browseVault = async () => {
    try {
      const picked = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "Vault", extensions: ["db"] }],
      });
      if (typeof picked === "string") settings.setCustomVaultPath(picked);
    } catch {
      /* dialog unavailable (e.g. browser preview) */
    }
  };

  const themes: ThemePref[] = ["dark", "light", "system"];
  const autoLockOptions: { v: AutoLockMinutes; label: string }[] = [
    { v: 1, label: "1 min" },
    { v: 5, label: "5 min" },
    { v: 15, label: "15 min" },
    { v: 0, label: "Never" },
  ];

  return (
    <div className="h-full flex-1 overflow-y-auto bg-bg">
      <div className="mx-auto max-w-2xl space-y-5 px-8 py-8">
        <h1 className="text-[20px] font-semibold tracking-tight text-text">Settings</h1>

        <Section title="Security">
          <form onSubmit={submitPw} className="space-y-3">
            <div>
              <label className="section-label mb-1.5 block">Current password</label>
              <PasswordInput
                value={oldPw}
                onChange={(e) => setOldPw(e.target.value)}
                className="font-mono"
              />
            </div>
            <div>
              <label className="section-label mb-1.5 block">New password</label>
              <PasswordInput
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                className="font-mono"
              />
            </div>
            <div>
              <label className="section-label mb-1.5 block">Confirm new password</label>
              <PasswordInput
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                className="font-mono"
              />
            </div>
            {pwMsg && (
              <p
                className={cn(
                  "text-[12.5px]",
                  pwMsg.ok ? "text-[color:var(--success)]" : "text-danger",
                )}
              >
                {pwMsg.text}
              </p>
            )}
            <Button
              type="submit"
              loading={pwBusy}
              disabled={!oldPw || !newPw}
              size="sm"
            >
              Change password
            </Button>
          </form>
        </Section>

        <Section title="Recovery codes">
          <p className="text-[12.5px] text-text-muted">
            Recovery codes let you reset your master password if you forget it.
            Regenerating creates a fresh set and <strong>invalidates all previous
            codes</strong>. The new codes are shown only once.
          </p>
          {codesErr && <p className="text-[12.5px] text-danger">{codesErr}</p>}
          <Button
            variant="secondary"
            size="sm"
            loading={codesBusy}
            onClick={async () => {
              setCodesErr(null);
              setCodesBusy(true);
              try {
                const codes = await regenerateRecoveryCodes();
                setNewCodes(codes);
              } catch (err) {
                setCodesErr(errMessage(err));
              } finally {
                setCodesBusy(false);
              }
            }}
          >
            <KeyRound className="h-4 w-4" /> Regenerate recovery codes
          </Button>
        </Section>

        <Section title="Backup & transfer">
          <p className="text-[12.5px] text-text-muted">
            Export all projects and secrets as plaintext <strong>JSON</strong>, or
            as an encrypted, passphrase-protected <strong>vault file</strong>.
            Import either format back later.
          </p>

          {transferMsg && (
            <p
              className={cn(
                "text-[12.5px]",
                transferMsg.ok ? "text-[color:var(--success)]" : "text-danger",
              )}
            >
              {transferMsg.text}
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setTransferMsg(null);
                setExportOpen(true);
              }}
            >
              <Download className="h-4 w-4" /> Export all
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => {
                setTransferMsg(null);
                setImportOpen(true);
              }}
            >
              <Upload className="h-4 w-4" /> Import
            </Button>
          </div>
        </Section>

        <Section title="Vault">
          <div>
            <label className="section-label mb-1.5 block">Vault file path</label>
            <div className="flex gap-2">
              <Input
                readOnly
                value={settings.customVaultPath ?? vaultPath ?? "default location"}
                className="font-mono text-text-muted"
              />
              <Button variant="secondary" size="md" onClick={browseVault}>
                <FolderOpen className="h-4 w-4" /> Browse
              </Button>
            </div>
            {settings.customVaultPath && (
              <p className="mt-2 text-[11.5px] text-text-dim">
                Custom path set. Lock and unlock to open this vault.{" "}
                <button
                  className="text-accent-fg underline"
                  onClick={() => settings.setCustomVaultPath(null)}
                >
                  Reset to default
                </button>
              </p>
            )}
          </div>
        </Section>

        <Section title="Auto-lock">
          <div>
            <label className="section-label mb-1.5 block">Lock after inactivity</label>
            <div className="flex gap-1.5">
              {autoLockOptions.map((o) => (
                <button
                  key={o.v}
                  onClick={() => settings.setAutoLock(o.v)}
                  className={cn(
                    "rounded-lg border px-3 py-1.5 text-[12.5px] transition-colors",
                    settings.autoLockMinutes === o.v
                      ? "border-accent bg-accent-soft text-text"
                      : "border-border text-text-muted hover:text-text",
                  )}
                >
                  {o.label}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="section-label mb-1.5 block">
              Clipboard auto-clear (seconds)
            </label>
            <Input
              type="number"
              min={0}
              value={settings.clipboardClearSeconds}
              onChange={(e) =>
                settings.setClipboardClear(Math.max(0, Number(e.target.value) || 0))
              }
              className="w-32 font-mono"
            />
          </div>
        </Section>

        <Section title="Appearance">
          <div>
            <label className="section-label mb-1.5 block">Theme</label>
            <div className="inline-flex rounded-lg border border-border p-0.5">
              {themes.map((t) => (
                <button
                  key={t}
                  onClick={() => {
                    settings.setTheme(t);
                    applyTheme(t);
                  }}
                  className={cn(
                    "rounded-md px-3 py-1.5 text-[12.5px] capitalize transition-colors",
                    settings.theme === t
                      ? "bg-accent-soft text-text"
                      : "text-text-muted hover:text-text",
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </Section>
      </div>

      <ExportOptionsDialog
        open={exportOpen}
        title="Export all data"
        onClose={() => setExportOpen(false)}
        doExport={exportAllFlow}
        onExported={() => setTransferMsg({ ok: true, text: "Export complete." })}
      />

      <ImportDialog
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={async (summary) => {
          await refreshProjects();
          setTransferMsg({ ok: true, text: `Imported: ${summarizeImport(summary)}` });
        }}
      />

      <Dialog
        open={newCodes !== null}
        onClose={() => setNewCodes(null)}
        title="Your new recovery codes"
      >
        {newCodes && (
          <RecoveryCodes
            codes={newCodes}
            onDone={() => setNewCodes(null)}
            doneLabel="Done"
          />
        )}
      </Dialog>
    </div>
  );
}
