"use client";

import { useState, useCallback } from "react";

function encodeBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const binStr = Array.from(bytes, (b) => String.fromCodePoint(b)).join("");
  return btoa(binStr);
}

function decodeBase64(input: string): string {
  const binStr = atob(input.trim());
  const bytes = Uint8Array.from(binStr, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function isValidBase64(str: string): boolean {
  try {
    return btoa(atob(str.trim())) === str.trim().replace(/\s/g, "");
  } catch {
    return false;
  }
}

export default function Base64Page() {
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [copied, setCopied] = useState(false);

  const flash = (text: string, type: "success" | "error") => {
    setMessage({ text, type });
    setTimeout(() => setMessage(null), 3000);
  };

  const handleEncode = useCallback(() => {
    if (!input.trim()) { flash("Enter something to encode.", "error"); return; }
    try {
      setOutput(encodeBase64(input));
      flash("Encoded successfully!", "success");
    } catch {
      flash("Failed to encode the text.", "error");
    }
  }, [input]);

  const handleDecode = useCallback(() => {
    if (!input.trim()) { flash("Enter something to decode.", "error"); return; }
    try {
      setOutput(decodeBase64(input));
      flash("Decoded successfully!", "success");
    } catch {
      flash("Invalid Base64. Check the input and try again.", "error");
    }
  }, [input]);

  const handleSwap = () => {
    if (!output) return;
    setInput(output);
    setOutput("");
    setMessage(null);
  };

  const handleClear = () => {
    setInput("");
    setOutput("");
    setMessage(null);
  };

  const handleCopy = async () => {
    if (!output) return;
    await navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const looksLikeBase64 = input.trim().length > 0 && isValidBase64(input.trim());

  return (
    <div className="space-y-6 p-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Base64 Encoder / Decoder</h1>
        <p className="text-zinc-400 text-sm mt-1">
          Encode text to Base64 or decode Base64 to plain text
        </p>
      </div>

      <div className="glass-card p-6 space-y-5">
        {/* Input */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
              Input
            </label>
            {looksLikeBase64 && (
              <span className="text-xs text-brand-green bg-brand-green/10 border border-brand-green/20 px-2 py-0.5 rounded-full">
                looks like Base64
              </span>
            )}
          </div>
          <textarea
            className="input-tech font-mono text-sm resize-none h-44"
            placeholder="Type or paste your text here..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
        </div>

        {/* Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={handleEncode} className="btn-primary text-sm">
            Encode →
          </button>
          <button onClick={handleDecode} className="btn-secondary text-sm">
            ← Decode
          </button>
          <button onClick={handleClear} className="btn-secondary text-sm">
            Clear
          </button>
          {output && (
            <button
              onClick={handleSwap}
              className="btn-secondary text-sm ml-auto"
              title="Use the result as new input"
            >
              ⇅ Use as input
            </button>
          )}
        </div>

        {/* Message */}
        {message && (
          <div
            className={`text-sm px-3 py-2 rounded-lg border ${
              message.type === "success"
                ? "bg-brand-green/10 text-brand-green border-brand-green/25"
                : "bg-red-500/10 text-red-400 border-red-500/25"
            }`}
          >
            {message.text}
          </div>
        )}

        {/* Output */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
              Output
            </label>
            {output && (
              <button
                onClick={handleCopy}
                className="text-xs font-medium text-brand-green hover:text-emerald-400 transition-colors"
              >
                {copied ? "✓ Copied!" : "Copy"}
              </button>
            )}
          </div>
          <textarea
            readOnly
            className="input-tech font-mono text-sm resize-none h-44 cursor-default"
            placeholder="The result will appear here..."
            value={output}
          />
        </div>
      </div>
    </div>
  );
}
