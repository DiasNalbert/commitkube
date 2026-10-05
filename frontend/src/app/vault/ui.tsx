"use client";

import { useCallback, useRef, useState } from "react";

export const IconLock = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-4 h-4">
    <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" />
  </svg>
);
export const IconShield = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
export const IconCopy = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
  </svg>
);
export const IconPlus = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);
export const IconTrash = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
  </svg>
);
export const IconUser = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" />
  </svg>
);
export const IconUsers = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" /><circle cx="9" cy="7" r="4" />
    <path d="M23 21v-2a4 4 0 00-3-3.87" /><path d="M16 3.13a4 4 0 010 7.75" />
  </svg>
);
export const IconEye = ({ off }: { off?: boolean }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" />
    {off && <line x1="1" y1="1" x2="23" y2="23" />}
  </svg>
);

/** A rough bit count, not a verdict. It is here to stop somebody choosing a
 *  passphrase that six weeks later turns out to have been the only thing
 *  between a database copy and every password in it. */
export function strengthOf(s: string): { bits: number; label: string; tone: string } {
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/[0-9]/.test(s)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(s)) pool += 30;
  const bits = s.length ? Math.round(s.length * Math.log2(pool || 1)) : 0;
  if (bits < 60) return { bits, label: "too weak", tone: "text-red-500 dark:text-red-400" };
  if (bits < 80) return { bits, label: "workable", tone: "text-amber-600 dark:text-amber-400" };
  if (bits < 110) return { bits, label: "good", tone: "text-sky-600 dark:text-sky-400" };
  return { bits, label: "strong", tone: "text-emerald-600 dark:text-emerald-400" };
}

/** Copies, then blanks the clipboard half a minute later. It is a courtesy,
 *  not a control -- anything that read the clipboard in those thirty seconds
 *  already has the password -- and it is worth having because the usual way a
 *  password escapes is being pasted into the wrong window an hour later. */
export function useClipboard() {
  const [copied, setCopied] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const copy = useCallback(async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setTimeout(() => setCopied(""), 1500);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => {});
      }, 30000);
    } catch {
      setCopied("");
    }
  }, []);
  return { copied, copy };
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

export const inputClass =
  "w-full bg-white/60 dark:bg-zinc-900/60 border border-zinc-300 dark:border-zinc-700 rounded px-2.5 py-1.5 text-sm outline-none focus:border-brand-green";
export const btnClass =
  "px-3 py-1.5 text-sm rounded border border-zinc-300 dark:border-zinc-700 hover:border-brand-green transition-colors disabled:opacity-50";
export const btnPrimary =
  "px-3 py-1.5 text-sm rounded bg-brand-green text-white hover:brightness-110 transition disabled:opacity-50";
export const selectClass =
  "bg-white/60 dark:bg-zinc-900/60 border border-zinc-300 dark:border-zinc-700 rounded px-2 py-1 text-xs outline-none focus:border-brand-green";

export const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** A six-digit field that takes what an authenticator shows, spaces and all,
 *  and keeps only the digits. */
export function CodeInput({ value, onChange, autoFocus }: {
  value: string;
  onChange: (v: string) => void;
  autoFocus?: boolean;
}) {
  return (
    <input
      className={`${inputClass} font-mono tracking-[0.4em] text-center max-w-[11rem]`}
      inputMode="numeric"
      autoComplete="one-time-code"
      placeholder="000000"
      maxLength={7}
      value={value}
      autoFocus={autoFocus}
      onChange={e => onChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
    />
  );
}

/** Shown once, and only once: the server never holds this in a form it could
 *  give back. Making the person tick a box is the difference between a code
 *  they saved and a code they scrolled past. */
export function RecoveryCode({ code, onDone }: { code: string; onDone: () => void }) {
  const [ack, setAck] = useState(false);
  const { copied, copy } = useClipboard();
  return (
    <div className="glass-card p-4 max-w-xl">
      <h2 className="font-semibold flex items-center gap-2"><IconShield /> Save your recovery code</h2>
      <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
        This is the only other way into your vault. It is not stored anywhere we can read,
        so if you lose both this and your passphrase, the contents are gone — there is no
        administrator who can recover them.
      </p>
      <div className="mt-3 font-mono text-sm tracking-wider bg-zinc-100 dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded p-3 break-all select-all">
        {code}
      </div>
      <div className="flex items-center gap-2 mt-3">
        <button className={btnClass} onClick={() => copy(code, "code")}>
          <span className="flex items-center gap-1.5"><IconCopy /> {copied ? "Copied" : "Copy"}</span>
        </button>
        <label className="flex items-center gap-2 text-sm ml-auto">
          <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />
          I have written it down
        </label>
        <button className={btnPrimary} disabled={!ack} onClick={onDone}>Continue</button>
      </div>
    </div>
  );
}
