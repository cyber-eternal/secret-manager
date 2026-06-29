// Project view: secret list (center) + secret detail (right).

import { useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router-dom";
import { Download, Pencil, Trash2 } from "lucide-react";
import { SecretList } from "../components/SecretList";
import { SecretDetail } from "../components/SecretDetail";
import { AddSecretDialog } from "../components/AddSecretDialog";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Dialog } from "../components/ui/Dialog";
import { Button, IconButton, Input, Spinner, Textarea } from "../components/ui/controls";
import { useVault } from "../store/vault";
import { listSecrets } from "../lib/tauri";
import { exportProjectFlow } from "../lib/transfer";
import { ExportOptionsDialog } from "../components/TransferDialogs";
import { errMessage } from "../lib/utils";
import type { SecretMeta } from "../lib/types";

export function Project() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { projects, setActiveProject, deleteProject, updateProject } = useVault();
  const project = projects.find((p) => p.id === id);

  const [secrets, setSecrets] = useState<SecretMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [confirmDel, setConfirmDel] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);

  const reload = useCallback(async () => {
    if (!id) return;
    try {
      const list = await listSecrets(id);
      setSecrets(list);
      setError(null);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    setActiveProject(id);
    setSelectedId(null);
    setLoading(true);
    reload();
  }, [id, reload, setActiveProject]);

  // Honor a secret pre-selection coming from the command palette.
  useEffect(() => {
    const pre = (location.state as { selectSecretId?: string } | null)?.selectSecretId;
    if (pre) {
      setSelectedId(pre);
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [location, navigate]);

  if (!project) {
    return (
      <div className="flex h-full flex-1 items-center justify-center text-[13px] text-text-muted">
        Project not found.
      </div>
    );
  }

  return (
    <div className="flex h-full min-w-0 flex-1">
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Project action bar */}
        <div className="flex items-center justify-end gap-2 border-b border-border-subtle bg-bg px-4 py-1.5">
          <Button variant="ghost" size="sm" onClick={() => setExportOpen(true)}>
            <Download className="h-4 w-4" /> Export
          </Button>
          <IconButton label="Edit project" onClick={() => setEditOpen(true)}>
            <Pencil className="h-4 w-4" />
          </IconButton>
          <IconButton label="Delete project" onClick={() => setConfirmDel(true)}>
            <Trash2 className="h-4 w-4" />
          </IconButton>
        </div>

        {loading ? (
          <div className="flex flex-1 items-center justify-center">
            <Spinner />
          </div>
        ) : error ? (
          <div className="flex flex-1 items-center justify-center text-[13px] text-danger">
            {error}
          </div>
        ) : (
          <SecretList
            project={project}
            secrets={secrets}
            selectedId={selectedId}
            onSelect={setSelectedId}
            onAdd={() => setAddOpen(true)}
          />
        )}
      </div>

      {selectedId && (
        <SecretDetail
          key={selectedId}
          secretId={selectedId}
          onClose={() => setSelectedId(null)}
          onChanged={reload}
        />
      )}

      <AddSecretDialog
        open={addOpen}
        projectId={project.id}
        onClose={() => setAddOpen(false)}
        onAdded={reload}
      />

      <EditProjectDialog
        open={editOpen}
        onClose={() => setEditOpen(false)}
        initialName={project.name}
        initialDescription={project.description ?? ""}
        onSave={async (name, description) => {
          await updateProject(project.id, { name, description: description || null });
          setEditOpen(false);
        }}
      />

      <ExportOptionsDialog
        open={exportOpen}
        title={`Export "${project.name}"`}
        onClose={() => setExportOpen(false)}
        doExport={(opts) => exportProjectFlow(project.id, project.name, opts)}
      />

      <ConfirmDialog
        open={confirmDel}
        title="Delete project"
        confirmText={project.name}
        message={
          <>
            Deleting <span className="font-mono text-text">{project.name}</span> removes
            all {secrets.length} secret(s) in it. This cannot be undone.
          </>
        }
        onConfirm={async () => {
          await deleteProject(project.id);
          setConfirmDel(false);
          navigate("/");
        }}
        onClose={() => setConfirmDel(false)}
      />
    </div>
  );
}

function EditProjectDialog({
  open,
  onClose,
  initialName,
  initialDescription,
  onSave,
}: {
  open: boolean;
  onClose: () => void;
  initialName: string;
  initialDescription: string;
  onSave: (name: string, description: string) => Promise<void>;
}) {
  const [name, setName] = useState(initialName);
  const [desc, setDesc] = useState(initialDescription);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setName(initialName);
      setDesc(initialDescription);
      setError(null);
    }
  }, [open, initialName, initialDescription]);

  return (
    <Dialog open={open} onClose={onClose} title="Edit project">
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await onSave(name.trim(), desc.trim());
          } catch (err) {
            setError(errMessage(err));
          } finally {
            setBusy(false);
          }
        }}
        className="space-y-4"
      >
        <div>
          <label className="section-label mb-1.5 block">Name</label>
          <Input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
        </div>
        <div>
          <label className="section-label mb-1.5 block">Description</label>
          <Textarea rows={2} value={desc} onChange={(e) => setDesc(e.target.value)} />
        </div>
        {error && <p className="text-[12.5px] text-danger">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={busy} disabled={!name.trim()}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
