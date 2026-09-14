"use client";

import { useEffect, useState } from "react";
import ThemeToggle from "@/app/components/ThemeToggle";
import KubeLogo from "@/app/components/KubeLogo";
import { API } from "@/lib/api";

export default function SetupPage() {
  const [isBootstrap, setIsBootstrap] = useState(false);
  const [tempUserId, setTempUserId] = useState<number>(0);

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
    const uid = localStorage.getItem("setup_user_id");
    const bootstrap = localStorage.getItem("setup_is_bootstrap");
    if (!uid) {
      window.location.href = "/login";
      return;
    }
    setTempUserId(Number(uid));
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
        temp_user_id: tempUserId,
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
    } catch (err: any) {
      setError(err.message);
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
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ temp_user_id: tempUserId, totp_code: totpCode }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Invalid code");

      localStorage.removeItem("setup_user_id");
      localStorage.removeItem("setup_is_bootstrap");
      localStorage.setItem("token", data.token);
      if (data.refresh_token) localStorage.setItem("refresh_token", data.refresh_token);
      if (data.user?.role) localStorage.setItem("role", data.user.role);
      window.location.href = "/";
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen relative">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-md px-4">
        <div className="flex justify-center mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brand-green/10 border border-brand-green/50 flex items-center justify-center tech-glow p-2">
              <KubeLogo className="w-full h-full" />
            </div>
            <span className="text-3xl font-black bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold">
              CommitKube
            </span>
          </div>
        </div>

        <div className="glass-card p-8 tech-glow">
          <div className="text-center mb-8">
            <h1 className="text-xl font-bold" style={{ color: "var(--color-fg)" }}>
              {isBootstrap ? "Create root account" : "Configure your account"}
            </h1>
            <p className="text-zinc-400 mt-1 text-sm">
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
                  <label className="block text-sm font-medium text-zinc-300 mb-2">Root user email</label>
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
                <label className="block text-sm font-medium text-zinc-300 mb-2">New password</label>
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
                <label className="block text-sm font-medium text-zinc-300 mb-2">Confirm password</label>
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
                    <img src={qrDataUrl} alt="QR Code MFA" width={220} height={220} />
                  </div>
                )}
                <p className="text-xs text-zinc-400 text-center">
                  Scan with Google Authenticator, Authy or similar.
                </p>
                <details className="w-full">
                  <summary className="text-xs text-zinc-500 cursor-pointer hover:text-zinc-300 text-center">
                    Can't scan — show manual code
                  </summary>
                  <div className="mt-2 p-3 bg-surface rounded-md border border-zinc-700 text-center">
                    <code className="text-sm font-mono text-brand-gold tracking-wider break-all">{mfaSecret}</code>
                  </div>
                </details>
              </div>

              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-2">
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
