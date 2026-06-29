import { useEffect } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Sidebar } from "./components/Sidebar";
import { CommandPalette } from "./components/CommandPalette";
import { UnlockScreen } from "./components/UnlockScreen";
import { RecoveryCodes } from "./components/RecoveryCodes";
import { Spinner } from "./components/ui/controls";
import { Home } from "./pages/Home";
import { Project } from "./pages/Project";
import { Settings } from "./pages/Settings";
import { useVault } from "./store/vault";
import { applyTheme, useSettings } from "./store/settings";

/** Auto-lock the vault after a period of inactivity. */
function useAutoLock() {
  const minutes = useSettings((s) => s.autoLockMinutes);
  const isUnlocked = useVault((s) => s.isUnlocked);

  useEffect(() => {
    if (!isUnlocked || minutes <= 0) return;
    let timer: ReturnType<typeof setTimeout>;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        void useVault.getState().lock();
      }, minutes * 60 * 1000);
    };
    const events = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [isUnlocked, minutes]);
}

function Shell() {
  return (
    <div className="flex h-full w-full overflow-hidden">
      <Sidebar />
      <main className="flex min-w-0 flex-1">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/projects/:id" element={<Project />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <CommandPalette />
    </div>
  );
}

export default function App() {
  const ready = useVault((s) => s.ready);
  const isUnlocked = useVault((s) => s.isUnlocked);
  const pendingCodes = useVault((s) => s.pendingRecoveryCodes);
  const ackCodes = useVault((s) => s.acknowledgeRecoveryCodes);
  const init = useVault((s) => s.init);
  const theme = useSettings((s) => s.theme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    void init();
  }, [init]);

  useAutoLock();

  if (!ready) {
    return (
      <div className="flex h-full w-full items-center justify-center bg-bg">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  if (pendingCodes) {
    return (
      <div className="flex h-full w-full items-center justify-center overflow-y-auto bg-bg p-6">
        <div className="w-[420px] rounded-2xl border border-border bg-surface p-7">
          <h1 className="mb-1 text-[18px] font-semibold text-text">
            Save your recovery codes
          </h1>
          <p className="mb-5 text-[13px] text-text-muted">
            Your vault is ready. Store these before continuing.
          </p>
          <RecoveryCodes
            codes={pendingCodes}
            onDone={ackCodes}
            doneLabel="Continue to vault"
          />
        </div>
      </div>
    );
  }

  if (!isUnlocked) return <UnlockScreen />;

  return <Shell />;
}
