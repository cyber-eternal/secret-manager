// Screenshot harness only: installs a fake Tauri IPC layer so the real UI can
// render with sample data in a plain browser. NOT shipped in the app bundle —
// this module is referenced only by the `screens.html` entry.

/* eslint-disable @typescript-eslint/no-explicit-any */

const now = Date.now();
const ago = (m: number) => now - m * 60_000;

const projects = [
  { id: "p1", name: "web-app", description: "Customer-facing dashboard", created_at: ago(9000), updated_at: ago(40) },
  { id: "p2", name: "infra", description: "Terraform + cloud creds", created_at: ago(20000), updated_at: ago(600) },
  { id: "p3", name: "payments", description: "Stripe & billing", created_at: ago(30000), updated_at: ago(1500) },
];

const secrets: Record<string, any> = {
  s1: { id: "s1", project_id: "p1", key: "DATABASE_URL", value: "postgres://app:s3cr3t@db.internal:5432/web", description: "Primary Postgres", tags: ["db", "prod"], created_at: ago(8000), updated_at: ago(40) },
  s2: { id: "s2", project_id: "p1", key: "STRIPE_SECRET_KEY", value: "sk_live_51Mxxxxxxxxxxxxxxxxxxxx", description: "Live key", tags: ["api", "prod"], created_at: ago(7000), updated_at: ago(120) },
  s3: { id: "s3", project_id: "p1", key: "JWT_SIGNING_SECRET", value: "hs256-7f3a9b2c1d8e4f6a", description: null, tags: ["auth"], created_at: ago(6000), updated_at: ago(300) },
  s4: { id: "s4", project_id: "p1", key: "SENTRY_DSN", value: "https://abc@o123.ingest.sentry.io/456", description: "Error monitoring", tags: ["monitoring"], created_at: ago(5000), updated_at: ago(900) },
  s5: { id: "s5", project_id: "p1", key: "REDIS_URL", value: "redis://cache.internal:6379/0", description: null, tags: ["db"], created_at: ago(4000), updated_at: ago(1300) },
};

const metaOf = (s: any) => ({ id: s.id, project_id: s.project_id, key: s.key, description: s.description, tags: s.tags, created_at: s.created_at, updated_at: s.updated_at });

function handle(cmd: string, args: any): any {
  switch (cmd) {
    case "vault_exists":
      return true;
    case "vault_has_recovery":
      return true;
    case "vault_is_unlocked":
      return new URLSearchParams(location.search).get("state") !== "locked";
    case "get_vault_path":
      return "~/Library/Application Support/secret-manager/vault.db";
    case "unlock_vault":
    case "create_vault":
      return cmd === "create_vault" ? ["A1B2C-D3E4F", "G5H6I-J7K8L"] : true;
    case "list_projects":
      return projects;
    case "get_project":
      return projects.find((p) => p.id === args.id);
    case "list_secrets":
      return Object.values(secrets).filter((s) => s.project_id === args.projectId).map(metaOf);
    case "get_secret":
      return secrets[args.id];
    case "search_secrets": {
      const q = (args.query ?? "").toLowerCase();
      return Object.values(secrets)
        .filter((s) => !q || s.key.toLowerCase().includes(q))
        .map(metaOf);
    }
    case "list_tags":
      return [];
    default:
      return null; // clipboard/dialog plugins etc.
  }
}

export function installMock() {
  (window as any).__TAURI_INTERNALS__ = {
    invoke: (cmd: string, args: any) => Promise.resolve(handle(cmd, args)),
    transformCallback: (cb: any) => cb,
    unregisterCallback: () => {},
    convertFileSrc: (p: string) => p,
  };
}
