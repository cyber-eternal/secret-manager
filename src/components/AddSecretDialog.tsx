// Modal to add a new secret to a project.

import { useState, type FormEvent } from "react";
import { Eye, EyeOff } from "lucide-react";
import { Button, IconButton, Input, Textarea } from "./ui/controls";
import { Dialog } from "./ui/Dialog";
import { TagInput } from "./TagInput";
import { addSecret } from "../lib/tauri";
import { errMessage } from "../lib/utils";

export function AddSecretDialog({
  open,
  projectId,
  onClose,
  onAdded,
}: {
  open: boolean;
  projectId: string;
  onClose: () => void;
  onAdded: () => void;
}) {
  const [key, setKey] = useState("");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [reveal, setReveal] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setKey("");
    setValue("");
    setDescription("");
    setTags([]);
    setReveal(false);
    setError(null);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await addSecret({
        projectId,
        key: key.trim(),
        value,
        description: description.trim() || null,
        tags,
      });
      reset();
      onAdded();
      onClose();
    } catch (err) {
      setError(errMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onClose={() => {
        reset();
        onClose();
      }}
      title="Add secret"
    >
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label className="section-label mb-1.5 block">Key</label>
          <Input
            autoFocus
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="DATABASE_URL"
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
              placeholder="••••••••"
              className="pr-10 font-mono"
            />
            <div className="absolute right-1 top-1">
              <IconButton
                label={reveal ? "Hide value" : "Reveal value"}
                type="button"
                onClick={() => setReveal((r) => !r)}
              >
                {reveal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </IconButton>
            </div>
          </div>
        </div>
        <div>
          <label className="section-label mb-1.5 block">Description (optional)</label>
          <Textarea
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What is this secret for?"
          />
        </div>
        <div>
          <label className="section-label mb-1.5 block">Tags</label>
          <TagInput value={tags} onChange={setTags} />
        </div>
        {error && <p className="text-[12.5px] text-danger">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              reset();
              onClose();
            }}
          >
            Cancel
          </Button>
          <Button type="submit" loading={busy} disabled={!key.trim()}>
            Add secret
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
