"use client";

import { useState } from "react";
import ThemeToggle from "@/app/components/ThemeToggle";
import { LogoMark } from "@/app/components/shell/icons";
import { API } from "@/lib/api";
import { safeNext } from "@/lib/auth";

/** A proxy or the server itself can answer in plain text (a 431 or a 502,
 *  say). Surface that text instead of a JSON parse error. */
/** The fields the sign-in endpoints answer with; any of them may be absent. */
interface AuthResponse {
  error?: string;
  setup_required?: boolean;
  setup_token?: string;
  is_bootstrap?: boolean;
  mfa_token?: string;
  token?: string;
  user?: { role?: string };
}

async function readJSON(res: Response): Promise<AuthResponse> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    // A gateway in front answers in HTML when the API is down or still
    // starting. Its markup means nothing to the person signing in.
    if (/^\s*</.test(text) || res.status >= 502) {
      return { error: `The server is not answering (${res.status}${res.statusText ? " " + res.statusText : ""}). It may be restarting; try again in a minute.` };
    }
    return { error: text.trim().slice(0, 300) || `${res.status} ${res.statusText}` };
  }
}

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [step, setStep] = useState<"credentials" | "mfa">("credentials");
  const [error, setError] = useState("");
  // Issued by the login call, which already checked the password. Naming
  // the account here instead would make the code the only factor.
  const [mfaToken, setMfaToken] = useState("");

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
        const data = await readJSON(res);
        if (!res.ok) throw new Error(data.error || "Login failed");

        if (data.setup_required) {
          localStorage.setItem("setup_token", data.setup_token ?? "");
          localStorage.setItem("setup_is_bootstrap", String(data.is_bootstrap));
          window.location.href = "/setup";
          return;
        }

        setMfaToken(data.mfa_token ?? "");
        setStep("mfa");
      } catch (err) {
        setError((err instanceof Error ? err.message : String(err)));
      }
    } else if (step === "mfa") {
      try {
        const res = await fetch(`${API}/auth/verify-mfa`, {
          method: "POST",
          // The answer sets the session cookie; without this a cross-origin
          // API (development) would have the browser discard it.
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mfa_token: mfaToken, code: mfaCode }),
        });
        const data = await readJSON(res);
        if (!res.ok) throw new Error(data.error || "MFA validation failed");

        // Nothing is stored: the session is the cookie the server just set,
        // and the next page asks it for an access token.
        window.location.href = safeNext(new URLSearchParams(window.location.search).get("next"));
      } catch (err) {
        setError((err instanceof Error ? err.message : String(err)));
      }
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
              {step === "credentials" ? "Sign in to your account" : "Two-factor authentication"}
            </h1>
            <p className="mt-1.5 text-[13px]" style={{ color: "var(--t3)" }}>
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
                  <label className="block text-sm font-medium mb-2">Email</label>
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
                  <label className="block text-sm font-medium mb-2">Password</label>
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
                <label className="block text-sm font-medium mb-2">6-digit code</label>
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
