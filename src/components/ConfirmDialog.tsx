// Confirmation dialog. When `confirmText` is set, the user must type it exactly
// to enable the destructive action (used for project deletion).

import { useState } from "react";
import { Button, Input } from "./ui/controls";
import { Dialog } from "./ui/Dialog";

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Delete",
  confirmText,
  onConfirm,
  onClose,
}: {
  open: boolean;
  title: string;
  message: React.ReactNode;
  confirmLabel?: string;
  confirmText?: string;
  onConfirm: () => void | Promise<void>;
  onClose: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const ready = (!confirmText || typed === confirmText) && !busy;

  const run = async () => {
    setBusy(true);
    try {
      await onConfirm();
      setTyped("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => {
        if (busy) return; // don't dismiss mid-action
        setTyped("");
        onClose();
      }}
      title={title}
    >
      <div className="space-y-4">
        <div className="text-[13px] text-text-secondary">{message}</div>
        {confirmText && (
          <div>
            <label className="section-label mb-1.5 block">
              Type <span className="font-mono text-text">{confirmText}</span> to confirm
            </label>
            <Input
              autoFocus
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              className="font-mono"
            />
          </div>
        )}
        <div className="flex justify-end gap-2">
          <Button
            variant="ghost"
            disabled={busy}
            onClick={() => {
              setTyped("");
              onClose();
            }}
          >
            Cancel
          </Button>
          <Button variant="danger" disabled={!ready} loading={busy} onClick={run}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
