"use client";

import { useEffect, useState, useCallback } from "react";
import { apiFetch } from "@/lib/api";

interface NotificationConfig {
  id: number;
  created_at: string;
  name: string;
  type: string;
  url: string;
  email: string;
  events: string;
  active: boolean;
}

const ALL_EVENTS = [
  { value: "scan.critical", label: "Critical scan findings" },
  { value: "pipeline.failed", label: "Pipeline failed" },
  { value: "repo.created", label: "Repository created" },
  { value: "repo.deleted", label: "Repository deleted" },
  { value: "app.degraded", label: "Application degraded / missing" },
  { value: "pod.restart_spike", label: "Pod restart spike" },
  { value: "node.down", label: "Node down / not ready" },
  { value: "node.high_cpu", label: "Node high CPU (>80%)" },
  { value: "node.high_memory", label: "Node high memory (>85%)" },
  { value: "pod.oom_killed", label: "Pod OOMKilled" },
  { value: "pod.crashloop", label: "Pod CrashLoopBackOff" },
  { value: "pod.image_pull_failed", label: "Pod image pull failed" },
  { value: "pod.config_error", label: "Pod config error (missing ConfigMap/Secret)" },
  { value: "pod.unschedulable", label: "Pod unschedulable" },
  { value: "pod.evicted", label: "Pod evicted" },
  { value: "pod.mem_pressure", label: "Pod memory pressure (>85% of limit)" },
  { value: "pod.cpu_throttling", label: "Pod CPU throttling (>25% of periods)" },
  { value: "pod.cpu_saturation", label: "Pod CPU saturation (>85% of limit)" },
  { value: "service.http_5xx", label: "Application returning server errors (5xx)" },
  { value: "service.error_logs", label: "Application logging errors / failed run" },
  { value: "service.dependency_failure", label: "Application cannot reach a dependency" },
];

const TYPE_LABELS: Record<string, { label: string; color: string }> = {
  teams:   { label: "Teams",   color: "text-blue-400 border-blue-400/30 bg-blue-400/10" },
  webhook: { label: "Webhook", color: "text-purple-400 border-purple-400/30 bg-purple-400/10" },
  email:   { label: "Email",   color: "text-brand-gold border-brand-gold/30 bg-brand-gold/10" },
};

const emptyForm = {
  name: "",
  type: "teams",
  url: "",
  email: "",
  events: [] as string[],
  active: true,
};

function parseEvents(eventsJSON: string): string[] {
  if (!eventsJSON) return [];
  try { return JSON.parse(eventsJSON); } catch { return []; }
}

function eventLabel(ev: string): string {
  return ALL_EVENTS.find(e => e.value === ev)?.label ?? ev;
}

export default function NotificationsPage() {
  const [configs, setConfigs] = useState<NotificationConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState({ ...emptyForm });
  const [saving, setSaving] = useState(false);
  const [testingId, setTestingId] = useState<number | null>(null);
  const [message, setMessage] = useState("");

  const msg = (m: string) => {
    setMessage(m);
    setTimeout(() => setMessage(""), 4000);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch("/notifications");
      if (res.ok) {
        const data = await res.json();
        setConfigs(Array.isArray(data) ? data : []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }
    load();
  }, [load]);

  const openCreate = () => {
    setEditingId(null);
    setForm({ ...emptyForm });
    setShowForm(true);
  };

  const openEdit = (cfg: NotificationConfig) => {
    setEditingId(cfg.id);
    setForm({
      name: cfg.name,
      type: cfg.type,
      url: cfg.url,
      email: cfg.email,
      events: parseEvents(cfg.events),
      active: cfg.active,
    });
    setShowForm(true);
  };

  const toggleEvent = (ev: string) => {
    setForm(prev => ({
      ...prev,
      events: prev.events.includes(ev)
        ? prev.events.filter(e => e !== ev)
        : [...prev.events, ev],
    }));
  };

  const handleSave = async () => {
    if (!form.name || !form.type) { msg("Name and type are required."); return; }
    if ((form.type === "teams" || form.type === "webhook") && !form.url) {
      msg("URL is required for this type."); return;
    }
    if (form.type === "email" && !form.email) {
      msg("Email address is required."); return;
    }

    setSaving(true);
    const payload = {
      name: form.name,
      type: form.type,
      url: form.url,
      email: form.email,
      events: JSON.stringify(form.events),
      active: form.active,
    };

    try {
      const res = editingId
        ? await apiFetch(`/notifications/${editingId}`, { method: "PUT", body: JSON.stringify(payload) })
        : await apiFetch("/notifications", { method: "POST", body: JSON.stringify(payload) });

      if (res.ok) {
        msg(editingId ? "Notification updated." : "Notification created.");
        setShowForm(false);
        load();
      } else {
        const err = await res.json().catch(() => ({ error: "Unknown error" }));
        msg(`Error: ${err.error || "Failed to save"}`);
      }
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this notification config?")) return;
    await apiFetch(`/notifications/${id}`, { method: "DELETE" });
    msg("Deleted.");
    load();
  };

  const handleToggleActive = async (cfg: NotificationConfig) => {
    await apiFetch(`/notifications/${cfg.id}`, {
      method: "PUT",
      body: JSON.stringify({
        name: cfg.name,
        type: cfg.type,
        url: cfg.url,
        email: cfg.email,
        events: cfg.events,
        active: !cfg.active,
      }),
    });
    load();
  };

  const handleTest = async (id: number) => {
    setTestingId(id);
    try {
      const res = await apiFetch(`/notifications/${id}/test`, { method: "POST" });
      if (res.ok) {
        msg("Test notification sent.");
      } else {
        const err = await res.json().catch(() => ({ error: "Unknown error" }));
        msg(`Test failed: ${err.error || "Unknown error"}`);
      }
    } finally {
      setTestingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold">Notifications</h1>
          <p className="text-zinc-400 mt-1">Configure where CommitKube sends alerts for key events.</p>
        </div>
        <button
          onClick={openCreate}
          className="px-4 py-2 rounded bg-brand-green text-black font-semibold text-sm hover:bg-brand-green/80 transition shrink-0"
        >
          + Add Notification
        </button>
      </header>

      {message && (
        <div className={`p-3 rounded border text-sm ${
          message.toLowerCase().startsWith("error") || message.toLowerCase().startsWith("test failed")
            ? "bg-red-500/10 border-red-500/40 text-red-400"
            : "bg-brand-green/10 border-brand-green/40 text-brand-green"
        }`}>
          {message}
        </div>
      )}

      {/* Create / Edit Form */}
      {showForm && (
        <div className="glass-card p-6 space-y-5">
          <h2 className="text-lg font-semibold text-brand-green">
            {editingId ? "Edit Notification" : "New Notification"}
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Name</label>
              <input
                type="text"
                value={form.name}
                onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g. Teams Critical Alerts"
                className="input-tech w-full text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Type</label>
              <select
                value={form.type}
                onChange={e => setForm(prev => ({ ...prev, type: e.target.value }))}
                className="input-tech w-full text-sm bg-zinc-900"
              >
                <option value="teams">Microsoft Teams</option>
                <option value="webhook">Webhook</option>
                <option value="email">Email</option>
              </select>
            </div>
          </div>

          {(form.type === "teams" || form.type === "webhook") && (
            <div>
              <label className="block text-xs text-zinc-400 mb-1">
                {form.type === "teams" ? "Teams Webhook URL" : "Webhook URL"}
              </label>
              <input
                type="url"
                value={form.url}
                onChange={e => setForm(prev => ({ ...prev, url: e.target.value }))}
                placeholder="https://..."
                className="input-tech w-full text-sm"
              />
            </div>
          )}

          {form.type === "email" && (
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Email Address</label>
              <input
                type="email"
                value={form.email}
                onChange={e => setForm(prev => ({ ...prev, email: e.target.value }))}
                placeholder="alerts@example.com"
                className="input-tech w-full text-sm"
              />
              <p className="text-xs text-zinc-500 mt-1">SMTP must be configured in Settings.</p>
            </div>
          )}

          <div>
            <label className="block text-xs text-zinc-400 mb-2">Events</label>
            <div className="flex flex-wrap gap-3">
              {ALL_EVENTS.map(ev => (
                <label key={ev.value} className="flex items-center gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={form.events.includes(ev.value)}
                    onChange={() => toggleEvent(ev.value)}
                    className="w-4 h-4 accent-brand-green"
                  />
                  <span className="text-sm text-zinc-300 group-hover:text-white transition">{ev.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.active}
                onChange={e => setForm(prev => ({ ...prev, active: e.target.checked }))}
                className="w-4 h-4 accent-brand-green"
              />
              <span className="text-sm text-zinc-300">Active</span>
            </label>
          </div>

          <div className="flex gap-3 pt-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-5 py-2 rounded bg-brand-green text-black font-semibold text-sm hover:bg-brand-green/80 transition disabled:opacity-50"
            >
              {saving ? "Saving..." : editingId ? "Save Changes" : "Create"}
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="px-5 py-2 rounded border border-zinc-700 text-zinc-300 text-sm hover:bg-zinc-800 transition"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Notification List */}
      {loading ? (
        <div className="text-center py-16 text-brand-green">Loading...</div>
      ) : configs.length === 0 ? (
        <div className="glass-card p-12 text-center text-zinc-500">
          No notification configs yet. Click <span className="text-brand-green">+ Add Notification</span> to get started.
        </div>
      ) : (
        <div className="glass-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-zinc-500 text-xs uppercase tracking-wide">
                <th className="text-left px-4 py-3">Name</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3 hidden md:table-cell">Events</th>
                <th className="text-left px-4 py-3 w-20">Status</th>
                <th className="text-right px-4 py-3 w-40">Actions</th>
              </tr>
            </thead>
            <tbody>
              {configs.map((cfg, i) => {
                const typeMeta = TYPE_LABELS[cfg.type] ?? { label: cfg.type, color: "text-zinc-400 border-zinc-600 bg-zinc-800/40" };
                const evList = parseEvents(cfg.events);
                return (
                  <tr
                    key={cfg.id}
                    className={`border-b border-zinc-800/60 hover:bg-zinc-800/30 transition-colors ${i % 2 === 0 ? "" : "bg-zinc-900/20"}`}
                  >
                    <td className="px-4 py-3 font-medium text-zinc-200">{cfg.name}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-medium ${typeMeta.color}`}>
                        {typeMeta.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 hidden md:table-cell">
                      {evList.length === 0 ? (
                        <span className="text-zinc-600">None</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {evList.map(ev => (
                            <span key={ev} className="px-1.5 py-0.5 rounded text-xs bg-zinc-800 text-zinc-400 border border-zinc-700">
                              {eventLabel(ev)}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleToggleActive(cfg)}
                        className={`text-xs font-medium px-2 py-0.5 rounded border transition ${
                          cfg.active
                            ? "text-brand-green border-brand-green/40 bg-brand-green/10 hover:bg-brand-green/20"
                            : "text-zinc-500 border-zinc-700 bg-zinc-800/40 hover:bg-zinc-700"
                        }`}
                      >
                        {cfg.active ? "Active" : "Inactive"}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleTest(cfg.id)}
                          disabled={testingId === cfg.id}
                          className="px-2.5 py-1 rounded text-xs border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition disabled:opacity-50"
                        >
                          {testingId === cfg.id ? "Testing..." : "Test"}
                        </button>
                        <button
                          onClick={() => openEdit(cfg)}
                          className="px-2.5 py-1 rounded text-xs border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDelete(cfg.id)}
                          className="px-2.5 py-1 rounded text-xs border border-red-900/50 text-red-400 hover:bg-red-900/20 transition"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
