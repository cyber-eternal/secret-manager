// Right-side detail panel: view/edit/delete a single secret. The decrypted
// value lives in local state only and is cleared on unmount / close.

import { useEffect, useState } from "react";
import { Check, Copy, Eye, EyeOff, Save, Trash2, X } from "lucide-react";
import { Button, IconButton, Input, Spinner, Textarea } from "./ui/controls";
import { TagInput } from "./TagInput";
import { ConfirmDialog } from "./ConfirmDialog";
import { getSecret, updateSecret, deleteSecret } from "../lib/tauri";
import { copyWithAutoClear } from "../lib/clipboard";
import { useSettings } from "../store/settings";
import { errMessage, formatRelativeTime } from "../lib/utils";
import type { Secret } from "../lib/types";

export function SecretDetail({
  secretId,
  onClose,
  onChanged,
}: {
  secretId: string;
  onClose: () => void;
  onChanged: () => void;
}) {
  const clipboardClear = useSettings((s) => s.clipboardClearSeconds);
  const [secret, setSecret] = useState<Secret | null>(null);
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [reveal, setReveal] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDel, setConfirmDel] = useState(false);

  useEffect(() => {
    let alive = true;
    setReveal(false);
    setError(null);
    getSecret(secretId)
      .then((s) => {
        if (!alive) return;
        setSecret(s);
        setKey(s.key);
        setValue(s.value);
        setDescription(s.description ?? "");
        setTags(s.tags);
      })
      .catch((e) => alive && setError(errMessage(e)));
    return () => {
      alive = false;
      // Clear plaintext from memory on navigation away.
      setValue("");
      setSecret(null);
    };
  }, [secretId]);

  const dirty =
    secret !== null &&
    (key !== secret.key ||
      value !== secret.value ||
      description !== (secret.description ?? "") ||
      JSON.stringify(tags) !== JSON.stringify(secret.tags));

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const updated = await updateSecret(secretId, {
        key: key.trim(),
        value,
        description: description.trim() || null,
        tags,
      });
      setSecret(updated);
      onChanged();
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    try {
      await copyWithAutoClear(value, clipboardClear);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (e) {
      setError(errMessage(e));
    }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await deleteSecret(secretId);
      onChanged();
      onClose();
    } catch (e) {
      setError(errMessage(e));
      setBusy(false);
    }
  };

  return (
    <aside className="flex h-full w-90 flex-col border-l border-border bg-panel">
      <div className="flex items-center justify-between border-b border-border-subtle px-4 py-3">
        <span className="section-label">Secret</span>
        <IconButton label="Close" onClick={onClose}>
          <X className="h-4 w-4" />
        </IconButton>
      </div>

      {!secret && !error && (
        <div className="flex flex-1 items-center justify-center">
          <Spinner />
        </div>
      )}

      {secret && (
        <div className="flex-1 space-y-4 overflow-y-auto p-4">
          <div>
            <label className="section-label mb-1.5 block">Key</label>
            <Input
              value={key}
              onChange={(e) => setKey(e.target.value)}
              className="font-mono"
            />
          </div>

          <div>
            <label className="section-label mb-1.5 block">Value</label>
            <div className="relative">
              <Input
                type={reveal ? "text" : "password"}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                className="pr-20 font-mono"
              />
              <div className="absolute right-1 top-1 flex">
                <IconButton
                  label={reveal ? "Hide value" : "Reveal value"}
                  type="button"
                  onClick={() => setReveal((r) => !r)}
                >
                  {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </IconButton>
                <IconButton label="Copy value" type="button" onClick={copy}>
                  {copied ? (
                    <Check className="h-4 w-4 text-[color:var(--success)]" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </IconButton>
              </div>
            </div>
          </div>

          <div>
            <label className="section-label mb-1.5 block">Description</label>
            <Textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional notes"
            />
          </div>

          <div>
            <label className="section-label mb-1.5 block">Tags</label>
            <TagInput value={tags} onChange={setTags} />
          </div>

          <div className="space-y-1 pt-1 text-[11.5px] text-text-dim">
            <div>Created {formatRelativeTime(secret.created_at)}</div>
            <div>Updated {formatRelativeTime(secret.updated_at)}</div>
          </div>

          {error && <p className="text-[12.5px] text-danger">{error}</p>}
        </div>
      )}

      {secret && (
        <div className="flex items-center justify-between gap-2 border-t border-border-subtle p-3">
          <Button
            variant="danger"
            size="sm"
            onClick={() => setConfirmDel(true)}
            disabled={busy}
          >
            <Trash2 className="h-4 w-4" /> Delete
          </Button>
          <Button size="sm" onClick={save} loading={busy} disabled={!dirty}>
            <Save className="h-4 w-4" /> Save
          </Button>
        </div>
      )}

      <ConfirmDialog
        open={confirmDel}
        title="Delete secret"
        message={
          <>
            Delete <span className="font-mono text-text">{secret?.key}</span>? This
            cannot be undone.
          </>
        }
        onConfirm={remove}
        onClose={() => setConfirmDel(false)}
      />
    </aside>
  );
}
