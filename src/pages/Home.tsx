// Landing inside the unlocked app: redirect to the first project, or show a
// welcome/empty state when there are none.

import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { FolderPlus, ShieldCheck } from "lucide-react";
import { useVault } from "../store/vault";

export function Home() {
  const navigate = useNavigate();
  const projects = useVault((s) => s.projects);

  useEffect(() => {
    if (projects.length > 0) {
      navigate(`/projects/${projects[0].id}`, { replace: true });
    }
  }, [projects, navigate]);

  if (projects.length > 0) return null;

  return (
    <div className="flex h-full flex-1 flex-col items-center justify-center gap-4 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent-soft text-accent-fg">
        <ShieldCheck className="h-8 w-8" />
      </div>
      <div>
        <p className="text-[16px] font-semibold text-text">Your vault is unlocked</p>
        <p className="mt-1 flex items-center gap-1.5 text-[13px] text-text-muted">
          <FolderPlus className="h-4 w-4" />
          Create a project from the sidebar to add your first secret.
        </p>
      </div>
    </div>
  );
}
