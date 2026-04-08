"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type SMTPConfig = { host: string; port: string; user: string; from: string };

type WebhookConfig = {
  id: number;
  alias: string;
  url: string;
  events: string;
  active: boolean;
  has_secret: boolean;
  created_at: string;
};

const ALL_EVENTS = [
  { value: "repo.created", label: "Repository created" },
  { value: "scan.completed", label: "Scan completed" },
  { value: "vulnerability.critical_found", label: "CRITICAL vulnerability found" },
  { value: "deploy.status_changed", label: "Deploy status changed" },
];

const emptyWebhook = { alias: "", url: "", secret: "", events: [] as string[], active: true };

export default function Settings() {
  const [message, setMessage] = useState("");
  const [userRole, setUserRole] = useState("");
  const [smtp, setSmtp] = useState<SMTPConfig>({ host: "", port: "587", user: "", from: "" });
  const [smtpPassword, setSmtpPassword] = useState("");
  const [smtpSaving, setSmtpSaving] = useState(false);

  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [showWebhookForm, setShowWebhookForm] = useState(false);
  const [editingWebhookId, setEditingWebhookId] = useState<number | null>(null);
  const [webhookForm, setWebhookForm] = useState(emptyWebhook);
  const [webhookSaving, setWebhookSaving] = useState(false);
  const [testingId, setTestingId] = useState<number | null>(null);

  const msg = (m: string) => { setMessage(m); setTimeout(() => setMessage(""), 4000); };

  const isAdmin = userRole === "admin" || userRole === "root";

  const loadWebhooks = async () => {
    const res = await apiFetch("/webhooks");
    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data)) setWebhooks(data);
    }
  };

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }

    const tokenData = JSON.parse(atob(token.split(".")[1]));
    setUserRole(tokenData.role || "");

    apiFetch("/smtp").then(r => r.json()).then(smtpData => {
      if (smtpData?.host !== undefined) setSmtp({ host: smtpData.host || "", port: smtpData.port || "587", user: smtpData.user || "", from: smtpData.from || "" });
    });

    loadWebhooks();
  }, []);

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <header>
        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold">
          Settings
        </h1>
        <p className="text-zinc-400 mt-1">
          System configuration. Manage credentials and integrations in{" "}
          <a href="/profile" className="text-brand-green hover:underline">Profile</a>.
        </p>
      </header>

      {message && (
        <div className={`p-3 rounded border text-sm ${message.startsWith("✅") ? "bg-brand-green/10 border-brand-green/40 text-brand-green" : "bg-red-500/10 border-red-500/40 text-red-400"}`}>
          {message}
        </div>
      )}

      <div className="glass-card p-6 border-l-4 border-l-brand-green">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold">Email (SMTP)</h2>
            <p className="text-zinc-400 text-sm mt-1">
              Used to send security scan reports.
              {userRole !== "admin" && userRole !== "root" && (
                <span className="ml-2 text-yellow-500 text-xs">Admin only</span>
              )}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">SMTP Host</label>
            <input
              className="input-tech text-sm"
              placeholder="smtp.gmail.com"
              value={smtp.host}
              onChange={e => setSmtp({ ...smtp, host: e.target.value })}
              disabled={userRole !== "admin" && userRole !== "root"}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Port</label>
            <input
              className="input-tech text-sm"
              placeholder="587"
              value={smtp.port}
              onChange={e => setSmtp({ ...smtp, port: e.target.value })}
              disabled={userRole !== "admin" && userRole !== "root"}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">User</label>
            <input
              className="input-tech text-sm"
              placeholder="noreply@company.com"
              value={smtp.user}
              onChange={e => setSmtp({ ...smtp, user: e.target.value })}
              disabled={userRole !== "admin" && userRole !== "root"}
            />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Password <span className="text-zinc-500">(leave blank to keep)</span></label>
            <input
              type="password"
              className="input-tech text-sm"
              placeholder="••••••••"
              value={smtpPassword}
              onChange={e => setSmtpPassword(e.target.value)}
              disabled={userRole !== "admin" && userRole !== "root"}
            />
          </div>
          <div className="md:col-span-2">
            <label className="text-xs text-zinc-400 mb-1 block">From <span className="text-zinc-500">(optional, defaults to user)</span></label>
            <input
              className="input-tech text-sm"
              placeholder="CommitKube <noreply@company.com>"
              value={smtp.from}
              onChange={e => setSmtp({ ...smtp, from: e.target.value })}
              disabled={userRole !== "admin" && userRole !== "root"}
            />
          </div>
        </div>

        {(userRole === "admin" || userRole === "root") && (
          <div className="flex justify-end mt-4">
            <button
              disabled={smtpSaving}
              onClick={async () => {
                setSmtpSaving(true);
                const res = await apiFetch("/smtp", { method: "PUT", body: JSON.stringify({ ...smtp, password: smtpPassword }) });
                const data = await res.json();
                setSmtpSaving(false);
                setSmtpPassword("");
                msg(res.ok ? "✅ SMTP saved!" : `❌ ${data.error}`);
              }}
              className="btn-primary text-sm px-4 py-1.5 disabled:opacity-50"
            >
              {smtpSaving ? "Saving..." : "Save SMTP"}
            </button>
          </div>
        )}
      </div>

      <div className="glass-card p-6 border-l-4 border-l-brand-gold">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold">Notification Webhooks</h2>
            <p className="text-zinc-400 text-sm mt-1">
              Send events to any HTTP URL — Slack, Teams, Discord, webhook.site, or your own endpoint.
              {!isAdmin && <span className="ml-2 text-yellow-500 text-xs">Admin only</span>}
            </p>
          </div>
          {isAdmin && (
            <button
              onClick={() => { setEditingWebhookId(null); setWebhookForm(emptyWebhook); setShowWebhookForm(true); }}
              className="btn-secondary text-sm px-3 py-1.5 shrink-0"
            >
              + Add
            </button>
          )}
        </div>

        {showWebhookForm && isAdmin && (
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-5 mb-4 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold">{editingWebhookId ? "Edit webhook" : "New webhook"}</h3>
              <button onClick={() => setShowWebhookForm(false)} className="text-zinc-500 hover:text-white">✕</button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Name / Alias *</label>
                <input
                  className="input-tech text-sm"
                  placeholder="e.g. Slack #alerts"
                  value={webhookForm.alias}
                  onChange={e => setWebhookForm({ ...webhookForm, alias: e.target.value })}
                />
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Destination URL *</label>
                <input
                  className="input-tech text-sm font-mono"
                  placeholder="https://hooks.slack.com/services/..."
                  value={webhookForm.url}
                  onChange={e => setWebhookForm({ ...webhookForm, url: e.target.value })}
                />
              </div>
              <div className="md:col-span-2">
                <label className="text-xs text-zinc-400 mb-1 block">
                  Secret <span className="text-zinc-600">(optional — used to sign the payload with HMAC-SHA256)</span>
                </label>
                <input
                  type="password"
                  className="input-tech text-sm font-mono"
                  placeholder="••••••••"
                  value={webhookForm.secret}
                  onChange={e => setWebhookForm({ ...webhookForm, secret: e.target.value })}
                />
              </div>
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-2 block">Events to receive</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ALL_EVENTS.map(ev => (
                  <label key={ev.value} className="flex items-center gap-2 cursor-pointer group">
                    <input
                      type="checkbox"
                      className="accent-brand-green"
                      checked={webhookForm.events.includes(ev.value)}
                      onChange={e => {
                        if (e.target.checked) {
                          setWebhookForm({ ...webhookForm, events: [...webhookForm.events, ev.value] });
                        } else {
                          setWebhookForm({ ...webhookForm, events: webhookForm.events.filter(x => x !== ev.value) });
                        }
                      }}
                    />
                    <span className="text-sm text-zinc-300 group-hover:text-white transition-colors">{ev.label}</span>
                    <code className="text-xs text-zinc-600 font-mono">{ev.value}</code>
                  </label>
                ))}
              </div>
              <p className="text-xs text-zinc-600 mt-2">None selected = receive all events.</p>
            </div>
            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-brand-green"
                  checked={webhookForm.active}
                  onChange={e => setWebhookForm({ ...webhookForm, active: e.target.checked })}
                />
                <span className="text-sm text-zinc-300">Active</span>
              </label>
              <div className="flex gap-3">
                <button onClick={() => setShowWebhookForm(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
                <button
                  disabled={webhookSaving}
                  className="btn-primary text-sm px-4 py-1.5 disabled:opacity-50"
                  onClick={async () => {
                    if (!webhookForm.alias || !webhookForm.url) { msg("❌ Alias and URL are required"); return; }
                    setWebhookSaving(true);
                    const body = {
                      alias: webhookForm.alias,
                      url: webhookForm.url,
                      secret: webhookForm.secret,
                      events: JSON.stringify(webhookForm.events),
                      active: webhookForm.active,
                    };
                    const res = editingWebhookId
                      ? await apiFetch(`/webhooks/${editingWebhookId}`, { method: "PUT", body: JSON.stringify(body) })
                      : await apiFetch("/webhooks", { method: "POST", body: JSON.stringify(body) });
                    const data = await res.json();
                    setWebhookSaving(false);
                    if (res.ok) {
                      msg("✅ Webhook saved!");
                      setShowWebhookForm(false);
                      loadWebhooks();
                    } else {
                      msg(`❌ ${data.error}`);
                    }
                  }}
                >
                  {webhookSaving ? "Saving..." : editingWebhookId ? "Save" : "Create webhook"}
                </button>
              </div>
            </div>
          </div>
        )}

        {webhooks.length === 0 ? (
          <p className="text-zinc-600 text-sm text-center py-6 border border-dashed border-zinc-800 rounded-lg">
            No webhooks configured. {isAdmin ? 'Click "+ Add" to get started.' : ""}
          </p>
        ) : (
          <div className="space-y-3">
            {webhooks.map(wh => {
              let parsedEvents: string[] = [];
              try { parsedEvents = JSON.parse(wh.events || "[]"); } catch { /* empty */ }
              return (
                <div key={wh.id} className={`flex items-center justify-between gap-4 p-4 rounded-lg border transition-colors ${wh.active ? "border-zinc-700 bg-zinc-900/30" : "border-zinc-800 bg-zinc-900/10 opacity-60"}`}>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-sm">{wh.alias}</span>
                      {!wh.active && <span className="text-xs text-zinc-500 border border-zinc-700 px-1.5 rounded">Inactive</span>}
                      {wh.has_secret && <span className="text-xs text-brand-green border border-brand-green/30 px-1.5 rounded">🔒 signed</span>}
                    </div>
                    <p className="text-xs text-zinc-500 font-mono truncate mt-0.5">{wh.url}</p>
                    {parsedEvents.length > 0 && (
                      <div className="flex gap-1 flex-wrap mt-1">
                        {parsedEvents.map(e => (
                          <span key={e} className="text-xs text-zinc-400 border border-zinc-800 px-1.5 py-0.5 rounded font-mono">{e}</span>
                        ))}
                      </div>
                    )}
                    {parsedEvents.length === 0 && (
                      <span className="text-xs text-zinc-600 mt-1 inline-block">all events</span>
                    )}
                  </div>
                  {isAdmin && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        disabled={testingId === wh.id}
                        onClick={async () => {
                          setTestingId(wh.id);
                          const res = await apiFetch(`/webhooks/${wh.id}/test`, { method: "POST" });
                          const data = await res.json();
                          setTestingId(null);
                          msg(res.ok ? `✅ Ping sent to ${wh.alias}` : `❌ ${data.error}`);
                        }}
                        className="text-xs text-zinc-400 hover:text-white border border-zinc-700 hover:border-zinc-500 px-3 py-1.5 rounded transition disabled:opacity-50"
                      >
                        {testingId === wh.id ? "Sending..." : "Test"}
                      </button>
                      <button
                        onClick={() => {
                          setEditingWebhookId(wh.id);
                          setWebhookForm({
                            alias: wh.alias,
                            url: wh.url,
                            secret: "",
                            events: (() => { try { return JSON.parse(wh.events || "[]"); } catch { return []; } })(),
                            active: wh.active,
                          });
                          setShowWebhookForm(true);
                        }}
                        className="btn-secondary text-xs px-3 py-1.5"
                      >
                        Edit
                      </button>
                      <button
                        onClick={async () => {
                          if (!confirm(`Remove webhook "${wh.alias}"?`)) return;
                          await apiFetch(`/webhooks/${wh.id}`, { method: "DELETE" });
                          msg("✅ Webhook removed");
                          loadWebhooks();
                        }}
                        className="text-xs text-red-500 hover:text-red-400 border border-red-500/30 hover:border-red-500/60 px-3 py-1.5 rounded transition"
                      >
                        Remove
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
