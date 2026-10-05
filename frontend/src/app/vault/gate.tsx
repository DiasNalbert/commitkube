"use client";

import { useEffect, useState } from "react";
import { normaliseRecoveryCode } from "@/lib/vault-crypto";
import {
  changePassphrase,
  confirmVaultMFA,
  fetchKeyring,
  hasVaultSession,
  recoverWithCode,
  setUpVault,
  startVaultMFA,
  unlock,
  verifyVaultCode,
  type Keyring,
} from "@/lib/vault-session";
import {
  btnClass, btnPrimary, CodeInput, errorText, Field, IconLock, IconShield, inputClass, RecoveryCode, strengthOf,
} from "./ui";

/** Step one, before anything else: an authenticator entry for the vault
 *  alone. It is a different seed from the sign-in one and is labelled
 *  "CommitKube Vault", so the two entries on the phone cannot be confused --
 *  and a code that signs somebody in never opens the vault. */
export function MFASetupPanel({ onDone }: { onDone: () => void }) {
  const [setup, setSetup] = useState<{ otpauth_url: string; secret: string } | null>(null);
  const [qr, setQr] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function begin() {
    setError("");
    setBusy(true);
    try {
      const s = await startVaultMFA();
      setSetup(s);
      const QRCode = (await import("qrcode")).default;
      setQr(await QRCode.toDataURL(s.otpauth_url, { width: 200, margin: 1 }));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function confirm(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await confirmVaultMFA(code);
      onDone();
    } catch (err) {
      setError(errorText(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="glass-card p-4 max-w-xl space-y-3">
      <div>
        <h2 className="font-semibold flex items-center gap-2"><IconShield /> Set up the vault code</h2>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
          The vault asks for its own six-digit code, separate from the one you use to sign in
          to CommitKube. Add it to your authenticator app as a new entry — it will appear as
          <span className="font-medium text-zinc-700 dark:text-zinc-200"> CommitKube Vault</span>.
          Your sign-in code will not open the vault, and this one will not sign you in.
        </p>
      </div>
      {!setup ? (
        <>
          {error && <p className="text-sm text-red-500">{error}</p>}
          <button className={btnPrimary} onClick={begin} disabled={busy}>
            {busy ? "Generating…" : "Generate vault code"}
          </button>
        </>
      ) : (
        <form onSubmit={confirm} className="space-y-3">
          <div className="flex flex-wrap gap-4 items-start">
            {qr && (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={qr} alt="QR code for the vault authenticator entry"
                className="rounded border border-zinc-300 dark:border-zinc-700 bg-white p-1" width={200} height={200} />
            )}
            <div className="min-w-0 flex-1 space-y-2">
              <p className="text-sm">Scan the code, or type this key into the app:</p>
              <code className="block font-mono text-xs break-all bg-zinc-100 dark:bg-zinc-900 rounded px-2 py-1 select-all">
                {setup.secret}
              </code>
              <Field label="Code from the new entry">
                <CodeInput value={code} onChange={setCode} autoFocus />
              </Field>
            </div>
          </div>
          {error && <p className="text-sm text-red-500">{error}</p>}
          <button className={btnPrimary} disabled={busy || code.length !== 6}>
            {busy ? "Checking…" : "Confirm"}
          </button>
        </form>
      )}
    </div>
  );
}

/** Asks for the vault code when there is no live vault session. Used before
 *  the first passphrase is chosen, when the page was reloaded between the
 *  two steps. */
export function CodePanel({ onDone }: { onDone: () => void }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await verifyVaultCode(code);
      onDone();
    } catch (err) {
      setError(errorText(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit} className="glass-card p-4 max-w-xl space-y-3">
      <h2 className="font-semibold flex items-center gap-2"><IconLock /> Vault code</h2>
      <p className="text-sm text-zinc-500 dark:text-zinc-400">
        Enter the code from the CommitKube Vault entry in your authenticator.
      </p>
      <CodeInput value={code} onChange={setCode} autoFocus />
      {error && <p className="text-sm text-red-500">{error}</p>}
      <button className={btnPrimary} disabled={busy || code.length !== 6}>{busy ? "Checking…" : "Continue"}</button>
    </form>
  );
}

export function SetupPanel({ onDone }: { onDone: () => void }) {
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [code, setCode] = useState("");
  const strength = strengthOf(pass);

  if (code) return <RecoveryCode code={code} onDone={onDone} />;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (pass !== confirm) return setError("the two passphrases do not match");
    if (strength.bits < 60) return setError("that passphrase is too weak to be the only thing protecting the vault");
    setBusy(true);
    try {
      setCode(await setUpVault(pass));
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="glass-card p-4 max-w-xl space-y-3">
      <div>
        <h2 className="font-semibold flex items-center gap-2"><IconShield /> Choose a vault passphrase</h2>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
          It is stretched in your browser and used to unlock a key that never leaves this tab —
          the server stores only sealed bytes and cannot read anything you put in the vault.
          Do not reuse your sign-in password. Your personal vault is created as soon as this is set.
        </p>
      </div>
      <Field label="Vault passphrase">
        <input type="password" className={inputClass} value={pass} autoFocus
          onChange={e => setPass(e.target.value)} />
      </Field>
      {pass && (
        <p className={`text-[11px] ${strength.tone}`}>
          about {strength.bits} bits — {strength.label}
        </p>
      )}
      <Field label="Confirm passphrase">
        <input type="password" className={inputClass} value={confirm}
          onChange={e => setConfirm(e.target.value)} />
      </Field>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <button className={btnPrimary} disabled={busy || !pass}>
        {busy ? "Deriving key…" : "Create vault"}
      </button>
    </form>
  );
}

/** Two things to get in: the vault code, which decides whether the server
 *  hands over the sealed key, and the passphrase, which is what opens it. A
 *  wrong passphrase keeps the session, so a typo does not burn a code. */
export function UnlockPanel({ onUnlocked }: { onUnlocked: (k: Keyring) => void }) {
  const [code, setCode] = useState("");
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"pass" | "recover">("pass");
  const [recovery, setRecovery] = useState("");
  const [newPass, setNewPass] = useState("");
  const [fresh, setFresh] = useState<{ code: string; keyring: Keyring } | null>(null);
  const [needCode, setNeedCode] = useState(!hasVaultSession());

  useEffect(() => { setNeedCode(!hasVaultSession()); }, []);

  if (fresh) return <RecoveryCode code={fresh.code} onDone={() => onUnlocked(fresh.keyring)} />;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    let stage = "code";
    try {
      if (!hasVaultSession()) {
        await verifyVaultCode(code);
        setNeedCode(false);
      }
      stage = "key";
      const keyring = await fetchKeyring();
      if (!keyring) throw new Error("your vault keys are missing");
      if (mode === "pass") {
        await unlock(keyring, pass);
        onUnlocked(keyring);
      } else {
        if (strengthOf(newPass).bits < 60) {
          stage = "weak";
          throw new Error("the new passphrase is too weak");
        }
        const next = await recoverWithCode(normaliseRecoveryCode(recovery), newPass);
        // The reset reseals the key under the new passphrase; open it with
        // that, so the person lands in the vault and not on a second prompt.
        const updated = await fetchKeyring();
        if (!updated) throw new Error("your vault keys are missing");
        await unlock(updated, newPass);
        setFresh({ code: next, keyring: updated });
      }
    } catch (err) {
      if (stage === "code" || stage === "weak") setError(errorText(err));
      else setError(mode === "pass"
        ? "that passphrase did not open the vault"
        : "that recovery code did not open the vault");
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  const ready = (!needCode || code.length === 6) &&
    (mode === "pass" ? Boolean(pass) : Boolean(recovery && newPass));

  return (
    <form onSubmit={submit} className="glass-card p-4 max-w-xl space-y-3">
      <h2 className="font-semibold flex items-center gap-2"><IconLock /> Vault locked</h2>
      {needCode && (
        <Field label="Vault code (CommitKube Vault in your authenticator)">
          <CodeInput value={code} onChange={setCode} autoFocus />
        </Field>
      )}
      {mode === "pass" ? (
        <>
          <Field label="Vault passphrase">
            <input type="password" className={inputClass} value={pass} autoFocus={!needCode}
              onChange={e => setPass(e.target.value)} />
          </Field>
          {error && <p className="text-sm text-red-500">{error}</p>}
          <div className="flex items-center gap-3">
            <button className={btnPrimary} disabled={busy || !ready}>
              {busy ? "Unlocking…" : "Unlock"}
            </button>
            <button type="button" className="text-sm text-zinc-500 hover:text-brand-green"
              onClick={() => { setMode("recover"); setError(""); }}>
              Forgot the passphrase?
            </button>
          </div>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            Lost the phone with the vault code? An administrator can reset it from IAM; your
            contents are not affected, because only your passphrase opens them.
          </p>
        </>
      ) : (
        <>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            The recovery code is used once. Resetting the passphrase issues a new one, which you
            will be shown on the next screen.
          </p>
          <Field label="Recovery code">
            <input className={`${inputClass} font-mono`} value={recovery}
              onChange={e => setRecovery(e.target.value)} placeholder="XXXXX-XXXXX-…" />
          </Field>
          <Field label="New passphrase">
            <input type="password" className={inputClass} value={newPass}
              onChange={e => setNewPass(e.target.value)} />
          </Field>
          {error && <p className="text-sm text-red-500">{error}</p>}
          <div className="flex items-center gap-3">
            <button className={btnPrimary} disabled={busy || !ready}>
              {busy ? "Working…" : "Reset passphrase"}
            </button>
            <button type="button" className="text-sm text-zinc-500 hover:text-brand-green"
              onClick={() => { setMode("pass"); setError(""); }}>
              Back
            </button>
          </div>
        </>
      )}
    </form>
  );
}

/** Changing a passphrase reseals the same identity, so nothing has to be
 *  re-shared and no other member notices. The old passphrase is asked for
 *  rather than the unlocked session being taken as proof: the point of the
 *  prompt is that it is still the same person at the keyboard. */
export function ChangePassphrase({ onClose }: { onClose: () => void }) {
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const strength = strengthOf(newPass);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (newPass !== confirm) return setError("the two passphrases do not match");
    if (strength.bits < 60) return setError("that passphrase is too weak");
    setBusy(true);
    try {
      const keyring = await fetchKeyring();
      if (!keyring) throw new Error("your vault keys are missing");
      await changePassphrase(keyring, oldPass, newPass);
      setDone(true);
    } catch {
      setError("the current passphrase did not open the vault");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="glass-card p-4 max-w-xl space-y-2">
        <p className="text-sm">Passphrase changed. Your recovery code is unchanged and still works.</p>
        <button className={btnPrimary} onClick={onClose}>Done</button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="glass-card p-4 max-w-xl space-y-3">
      <h3 className="font-semibold text-sm">Change vault passphrase</h3>
      <Field label="Current passphrase">
        <input type="password" className={inputClass} value={oldPass} autoFocus
          onChange={e => setOldPass(e.target.value)} />
      </Field>
      <Field label="New passphrase">
        <input type="password" className={inputClass} value={newPass}
          onChange={e => setNewPass(e.target.value)} />
      </Field>
      {newPass && <p className={`text-[11px] ${strength.tone}`}>about {strength.bits} bits — {strength.label}</p>}
      <Field label="Confirm new passphrase">
        <input type="password" className={inputClass} value={confirm}
          onChange={e => setConfirm(e.target.value)} />
      </Field>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="flex gap-2">
        <button className={btnPrimary} disabled={busy || !oldPass || !newPass}>
          {busy ? "Deriving key…" : "Change passphrase"}
        </button>
        <button type="button" className={btnClass} onClick={onClose}>Cancel</button>
      </div>
    </form>
  );
}
