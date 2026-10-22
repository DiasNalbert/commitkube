"use client";

import { useEffect, useState } from "react";
import ThemeToggle from "@/app/components/ThemeToggle";
import { LogoMark } from "@/app/components/shell/icons";
import { API } from "@/lib/api";

export default function SetupPage() {
  const [isBootstrap, setIsBootstrap] = useState(false);
  // Issued by the login call, which already verified the password. Naming the
  // account here instead is what let anyone start setup for any account.
  const [setupToken, setSetupToken] = useState("");

  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [qrDataUrl, setQrDataUrl] = useState("");
  const [mfaSecret, setMfaSecret] = useState("");
  const [totpCode, setTotpCode] = useState("");

  const [step, setStep] = useState<"credentials" | "qr">("credentials");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const ticket = localStorage.getItem("setup_token");
    const bootstrap = localStorage.getItem("setup_is_bootstrap");
    if (!ticket) {
      window.location.href = "/login";
      return;
    }
    setSetupToken(ticket);
    setIsBootstrap(bootstrap === "true");
  }, []);

  const handleCredentials = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (newPassword.length < 6) {
      setError("Password must be at least 6 characters.");
      return;
    }

    setLoading(true);
    try {
      const body: Record<string, unknown> = {
        setup_token: setupToken,
        new_password: newPassword,
      };
      if (isBootstrap) body.new_email = newEmail;

      const res = await fetch(`${API}/auth/setup-init`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to start setup");

      const QRCode = (await import("qrcode")).default;
      const dataUrl = await QRCode.toDataURL(data.mfa_url, { width: 220 });
      setQrDataUrl(dataUrl);
      setMfaSecret(data.mfa_secret);
      setStep("qr");
    } catch (err) {
      setError((err instanceof Error ? err.message : String(err)));
    } finally {
      setLoading(false);
    }
  };

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API}/auth/setup-confirm`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ setup_token: setupToken, totp_code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Invalid code");

      localStorage.removeItem("setup_token");
      localStorage.removeItem("setup_is_bootstrap");
      window.location.href = "/";
    } catch (err) {
      setError((err instanceof Error ? err.message : String(err)));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen relative">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-[400px] px-4">
        <div className="flex items-center gap-2.5 mb-8">
          <LogoMark className="w-[26px] h-[26px]" />
          <span className="text-[22px] font-bold tracking-[-0.02em]">CommitKube</span>
        </div>

        <div className="p-8" style={{ background: "var(--card)", border: "1px solid var(--rule)", borderRadius: 4 }}>
          <div className="mb-7">
            <h1 className="text-[22px] font-medium tracking-[-0.02em] m-0">
              {isBootstrap ? "Create root account" : "Configure your account"}
            </h1>
            <p className="mt-1.5 text-[13px]" style={{ color: "var(--t3)" }}>
              {step === "credentials"
                ? isBootstrap
                  ? "Set the root user credentials"
                  : "Set your password and configure the authenticator"
                : "Scan the QR code with your authenticator app"}
            </p>
          </div>

          <div className="flex items-center justify-center gap-2 mb-8">
            <div className={`w-2.5 h-2.5 rounded-full transition-colors ${step === "credentials" ? "bg-brand-green" : "bg-brand-green/40"}`} />
            <div className="w-8 h-px bg-zinc-700" />
            <div className={`w-2.5 h-2.5 rounded-full transition-colors ${step === "qr" ? "bg-brand-green" : "bg-zinc-600"}`} />
          </div>

          {error && (
            <div className="mb-6 p-3 rounded-md bg-red-500/10 border border-red-500/50 text-red-400 text-sm text-center">
              {error}
            </div>
          )}

          {step === "credentials" && (
            <form onSubmit={handleCredentials} className="space-y-5">
              {isBootstrap && (
                <div>
                  <label className="block text-sm font-medium mb-2">Root user email</label>
                  <input
                    type="email"
                    required
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    className="input-tech"
                    placeholder="root@company.com"
                  />
                </div>
              )}
              <div>
                <label className="block text-sm font-medium mb-2">New password</label>
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="input-tech"
                  placeholder="••••••••"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Confirm password</label>
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="input-tech"
                  placeholder="••••••••"
                />
              </div>
              <button type="submit" disabled={loading} className="w-full btn-primary py-3 text-base mt-2">
                {loading ? "Generating QR code..." : "Continue"}
              </button>
            </form>
          )}

          {step === "qr" && (
            <form onSubmit={handleConfirm} className="space-y-5">
              <div className="flex flex-col items-center gap-4">
                {qrDataUrl && (
                  <div className="p-3 bg-white rounded-xl">
                    {/* A data: URL generated in the browser; next/image has nothing to optimise here. */}
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img src={qrDataUrl} alt="QR Code MFA" width={220} height={220} />
                  </div>
                )}
                <p className="text-xs text-zinc-400 text-center">
                  Scan with Google Authenticator, Authy or similar.
                </p>
                <details className="w-full">
                  <summary className="text-xs text-zinc-500 cursor-pointer hover:text-zinc-300 text-center">
                    Can&apos;t scan — show manual code
                  </summary>
                  <div className="mt-2 p-3 bg-surface rounded-md border border-zinc-700 text-center">
                    <code className="text-sm font-mono text-brand-gold tracking-wider break-all">{mfaSecret}</code>
                  </div>
                </details>
              </div>

              <div>
                <label className="block text-sm font-medium mb-2">
                  Verification code (6 digits)
                </label>
                <input
                  type="text"
                  required
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  className="input-tech text-center tracking-widest text-lg font-mono"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>

              <button type="submit" disabled={loading} className="w-full btn-primary py-3 text-base">
                {loading ? "Verifying..." : "Confirm and sign in"}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
