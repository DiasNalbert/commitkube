"use client";

import { useState } from "react";
import ThemeToggle from "@/app/components/ThemeToggle";
import KubeLogo from "@/app/components/KubeLogo";
import { API } from "@/lib/api";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [step, setStep] = useState<"credentials" | "mfa">("credentials");
  const [error, setError] = useState("");
  const [tempUserId, setTempUserId] = useState<number>(0);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (step === "credentials") {
      try {
        const res = await fetch(`${API}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Login failed");

        if (data.setup_required) {
          localStorage.setItem("setup_user_id", String(data.temp_user_id));
          localStorage.setItem("setup_is_bootstrap", String(data.is_bootstrap));
          window.location.href = "/setup";
          return;
        }

        setTempUserId(data.temp_user_id);
        setStep("mfa");
      } catch (err: any) {
        setError(err.message);
      }
    } else if (step === "mfa") {
      try {
        const res = await fetch(`${API}/auth/verify-mfa`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_id: tempUserId, code: mfaCode }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "MFA validation failed");

        localStorage.setItem("token", data.token);
        if (data.refresh_token) localStorage.setItem("refresh_token", data.refresh_token);
        if (data.user?.role) localStorage.setItem("role", data.user.role);
        window.location.href = "/";
      } catch (err: any) {
        setError(err.message);
      }
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
              {step === "credentials" ? "Sign in to your account" : "Two-factor authentication"}
            </h1>
            <p className="text-zinc-400 mt-1 text-sm">
              {step === "credentials" ? "Enter your email and password" : "Enter the 6-digit code from your authenticator app"}
            </p>
          </div>

          {error && (
            <div className="mb-6 p-3 rounded-md bg-red-500/10 border border-red-500/50 text-red-400 text-sm text-center">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {step === "credentials" && (
              <>
                <div>
                  <label className="block text-sm font-medium text-zinc-300 mb-2">Email</label>
                  <input
                    type="text"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="input-tech"
                    placeholder="you@email.com"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-zinc-300 mb-2">Password</label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="input-tech pr-10"
                      placeholder="••••••••"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(v => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-200 transition"
                      tabIndex={-1}
                    >
                      {showPassword ? (
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                        </svg>
                      ) : (
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                        </svg>
                      )}
                    </button>
                  </div>
                </div>
              </>
            )}

            {step === "mfa" && (
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-2">6-digit code</label>
                <input
                  type="text"
                  required
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  className="input-tech text-center tracking-widest text-lg font-mono"
                  placeholder="000000"
                  maxLength={6}
                />
              </div>
            )}

            <button type="submit" className="w-full btn-primary py-3 text-base mt-4">
              {step === "credentials" ? "Sign in" : "Verify code"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
