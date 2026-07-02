// Full-screen gate: create vault (first run), unlock, or recover with a code.

import { useEffect, useState, type FormEvent } from "react";
import { Fingerprint, KeyRound, LifeBuoy, Lock, ShieldPlus } from "lucide-react";
import { Button, Input, PasswordInput } from "./ui/controls";
import { ConfirmDialog } from "./ConfirmDialog";
import { StrengthMeter } from "./StrengthMeter";
import { estimateStrength, isWeak } from "../lib/passwordStrength";
import { useVault } from "../store/vault";
import { useSettings } from "../store/settings";
import { errMessage, validateMasterPassword } from "../lib/utils";
import {
  biometricAvailable as api_biometricAvailable,
  biometricEnrolled as api_biometricEnrolled,
} from "../lib/tauri";

type Mode = "auth" | "recover";

export function UnlockScreen() {
  const { hasVault, unlock, createVault, recover, resetVault, busy, biometricUnlock } =
    useVault();
  const [mode, setMode] = useState<Mode>("auth");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [showReset, setShowReset] = useState(false);
  const [weakAck, setWeakAck] = useState(false);
  const [lockedFor, setLockedFor] = useState(0);
  const [bioReady, setBioReady] = useState(false);

  const firstRun = !hasVault;

  useEffect(() => {
    if (lockedFor <= 0) return;
    const t = setInterval(() => setLockedFor((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(t);
  }, [lockedFor]);

  const customVaultPath = useSettings((s) => s.customVaultPath);

  useEffect(() => {
    if (firstRun) return;
    Promise.all([
      api_biometricAvailable(),
      api_biometricEnrolled(customVaultPath ?? undefined),
    ])
      .then(([a, e]) => setBioReady(a && e))
      .catch(() => setBioReady(false));
  }, [firstRun, customVaultPath]);

  const resetFields = () => {
    setPassword("");
    setConfirm("");
    setCode("");
    setError(null);
    setWeakAck(false);
  };

  const onAuthSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      if (firstRun) {
        const check = validateMasterPassword(password, confirm);
        if (!check.ok) return setError(check.message ?? "Invalid password");
        if (isWeak(estimateStrength(password).score) && !weakAck) {
          setWeakAck(true);
          return setError("That password is weak. Click Create vault again to use it anyway.");
        }
        await createVault(password);
      } else {
        if (!password) return setError("Enter your master password.");
        await unlock(password);
      }
      resetFields();
    } catch (err) {
      const msg = errMessage(err);
      const m = msg.match(/try again in (\d+)s/i);
      if (m) setLockedFor(parseInt(m[1], 10));
      setError(msg);
    }
  };

  const onRecoverSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!code.trim()) return setError("Enter a recovery code.");
    const check = validateMasterPassword(password, confirm);
    if (!check.ok) return setError(check.message ?? "Invalid password");
    if (isWeak(estimateStrength(password).score) && !weakAck) {
      setWeakAck(true);
      return setError("That password is weak. Click Recover access again to use it anyway.");
    }
    try {
      await recover(code.trim(), password);
      resetFields();
    } catch (err) {
      setError(errMessage(err));
    }
  };

  return (
    <div className="relative flex h-full w-full items-center justify-center overflow-hidden bg-bg">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(60% 50% at 50% 30%, var(--accent-soft), transparent 70%)",
        }}
      />

      <div className="relative z-10 w-[380px] rounded-2xl border border-border bg-surface/80 p-8 backdrop-blur">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-accent-soft text-accent-fg">
            {mode === "recover" ? (
              <LifeBuoy className="h-6 w-6" />
            ) : (
              <Lock className="h-6 w-6" />
            )}
          </div>
          <h1 className="text-[19px] font-semibold text-text">
            {mode === "recover"
              ? "Recover access"
              : firstRun
                ? "Create your vault"
                : "Unlock vault"}
          </h1>
          <p className="mt-1 text-[13px] text-text-muted">
            {mode === "recover"
              ? "Enter a recovery code and choose a new password."
              : firstRun
                ? "Choose a master password. It is never stored."
                : "Enter your master password to continue."}
          </p>
        </div>

        {mode === "auth" ? (
          <form onSubmit={onAuthSubmit}>
            <label className="section-label mb-1.5 block">Master password</label>
            <PasswordInput
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="font-mono"
            />
            {firstRun && (
              <>
                <label className="section-label mb-1.5 mt-4 block">
                  Confirm password
                </label>
                <PasswordInput
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="••••••••"
                  className="font-mono"
                />
              </>
            )}
            {firstRun && <StrengthMeter password={password} />}

            {error && (
              <p className="mt-3 text-[12.5px] text-danger" role="alert">
                {error}
              </p>
            )}

            <Button
              type="submit"
              loading={busy}
              disabled={!firstRun && lockedFor > 0}
              className="mt-6 w-full"
            >
              {firstRun ? (
                <>
                  <ShieldPlus className="h-4 w-4" /> Create vault
                </>
              ) : lockedFor > 0 ? (
                <>Locked — retry in {lockedFor}s</>
              ) : (
                <>
                  <KeyRound className="h-4 w-4" /> Unlock
                </>
              )}
            </Button>

            {!firstRun && bioReady && (
              <Button
                type="button"
                variant="ghost"
                onClick={async () => {
                  setError(null);
                  try {
                    await biometricUnlock();
                    resetFields();
                  } catch (err) {
                    setError(errMessage(err));
                  }
                }}
                className="mt-3 w-full"
              >
                <Fingerprint className="h-4 w-4" /> Unlock with Touch ID
              </Button>
            )}

            {!firstRun && (
              <button
                type="button"
                onClick={() => {
                  resetFields();
                  setMode("recover");
                }}
                className="mt-4 block w-full text-center text-[12.5px] text-accent-fg hover:underline"
              >
                Forgot your password?
              </button>
            )}
            {firstRun && (
              <p className="mt-4 text-center text-[11.5px] text-text-dim">
                If you forget this password, you'll need a recovery code to get back in.
              </p>
            )}
          </form>
        ) : (
          <form onSubmit={onRecoverSubmit}>
            <label className="section-label mb-1.5 block">Recovery code</label>
            <Input
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
              className="font-mono"
            />
            <label className="section-label mb-1.5 mt-4 block">New password</label>
            <PasswordInput
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="font-mono"
            />
            <label className="section-label mb-1.5 mt-4 block">Confirm new password</label>
            <PasswordInput
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="••••••••"
              className="font-mono"
            />
            <StrengthMeter password={password} />

            {error && (
              <p className="mt-3 text-[12.5px] text-danger" role="alert">
                {error}
              </p>
            )}

            <Button type="submit" loading={busy} className="mt-6 w-full">
              <LifeBuoy className="h-4 w-4" /> Recover access
            </Button>

            <div className="mt-4 flex items-center justify-between text-[12.5px]">
              <button
                type="button"
                onClick={() => {
                  resetFields();
                  setMode("auth");
                }}
                className="text-text-muted hover:text-text"
              >
                ← Back to unlock
              </button>
              <button
                type="button"
                onClick={() => setShowReset(true)}
                className="text-danger hover:underline"
              >
                Lost your codes?
              </button>
            </div>
          </form>
        )}
      </div>

      <ConfirmDialog
        open={showReset}
        title="Delete vault and start over"
        confirmText="DELETE"
        confirmLabel="Delete vault"
        message={
          <>
            Without your master password or a recovery code, this vault{" "}
            <strong>cannot</strong> be decrypted — there is no backdoor. You can
            permanently delete it and create a new one. All stored secrets will be
            lost.
          </>
        }
        onConfirm={async () => {
          setShowReset(false);
          resetFields();
          setMode("auth");
          try {
            await resetVault();
          } catch (err) {
            setError(errMessage(err));
          }
        }}
        onClose={() => setShowReset(false)}
      />
    </div>
  );
}
