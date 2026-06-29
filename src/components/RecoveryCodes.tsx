// Presents one-time recovery codes. Codes are shown once and cannot be
// retrieved later — the user must save them now.

import { useState } from "react";
import { Check, Copy, Download, ShieldAlert } from "lucide-react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Button } from "./ui/controls";

export function RecoveryCodes({
  codes,
  onDone,
  doneLabel = "I've saved them",
}: {
  codes: string[];
  onDone: () => void;
  doneLabel?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  const text = codes.join("\n");

  const copyAll = async () => {
    try {
      await writeText(text);
    } catch {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        /* ignore */
      }
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const download = () => {
    try {
      const blob = new Blob(
        [
          "secret-manager recovery codes\n",
          "Keep these somewhere safe. Each code works once to reset your master password.\n\n",
          text,
          "\n",
        ],
        { type: "text/plain" },
      );
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "secret-manager-recovery-codes.txt";
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      /* download may be unavailable in the webview; copy is the fallback */
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-lg border border-[color:var(--accent)]/30 bg-accent-soft px-3 py-2.5 text-[12.5px] text-text-secondary">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-accent-fg" />
        <p>
          Save these recovery codes now. If you forget your master password, a code
          lets you reset it. They are shown <strong>only once</strong> and each works
          a single time.
        </p>
      </div>

      <ul className="grid grid-cols-2 gap-2">
        {codes.map((c) => (
          <li
            key={c}
            className="rounded-lg border border-border bg-surface px-3 py-2 text-center font-mono text-[12.5px] tracking-wide text-text"
          >
            {c}
          </li>
        ))}
      </ul>

      <div className="flex gap-2">
        <Button variant="secondary" size="sm" onClick={copyAll} className="flex-1">
          {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          {copied ? "Copied" : "Copy all"}
        </Button>
        <Button variant="secondary" size="sm" onClick={download} className="flex-1">
          <Download className="h-4 w-4" /> Download
        </Button>
      </div>

      <label className="flex items-center gap-2 text-[12.5px] text-text-secondary">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="h-4 w-4 accent-[color:var(--accent)]"
        />
        I have saved my recovery codes somewhere safe.
      </label>

      <Button className="w-full" disabled={!confirmed} onClick={onDone}>
        {doneLabel}
      </Button>
    </div>
  );
}
