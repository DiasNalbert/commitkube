"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type FieldDef = {
  key: string;
  label: string;
  type: "string" | "number" | "select" | "bool";
  required: boolean;
  options?: string[];
  validation?: string;
  default?: string;
};

type GoldenPath = {
  id: number;
  name: string;
  description: string;
  fields_schema: string;
  resource_limits: string;
  allowed_namespaces: string;
  required_labels: string;
  approval_workflow: "none" | "manual";
  is_active: boolean;
  created_at: string;
};

const emptyForm = {
  name: "",
  description: "",
  approval_workflow: "none" as "none" | "manual",
  allowed_namespaces: "",
  is_active: true,
};

const emptyField: FieldDef = {
  key: "",
  label: "",
  type: "string",
  required: false,
  options: [],
  validation: "",
  default: "",
};

export default function GoldenPathsPage() {
  const [userRole, setUserRole] = useState("");
  const [paths, setPaths] = useState<GoldenPath[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState("");

  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [fields, setFields] = useState<FieldDef[]>([]);
  const [saving, setSaving] = useState(false);

  const [expandedId, setExpandedId] = useState<number | null>(null);

  const msg = (m: string) => { setMessage(m); setTimeout(() => setMessage(""), 4000); };

  const isAdmin = userRole === "admin" || userRole === "root";

  const load = async () => {
    const res = await apiFetch("/golden-paths");
    const data = await res.json();
    if (Array.isArray(data)) setPaths(data);
    setLoading(false);
  };

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }
    const tokenData = JSON.parse(atob(token.split(".")[1]));
    setUserRole(tokenData.role || "");
    load();
  }, []);

  const openCreate = () => {
    setEditingId(null);
    setForm(emptyForm);
    setFields([]);
    setShowForm(true);
  };

  const openEdit = (gp: GoldenPath) => {
    setEditingId(gp.id);
    setForm({
      name: gp.name,
      description: gp.description,
      approval_workflow: gp.approval_workflow,
      allowed_namespaces: gp.allowed_namespaces,
      is_active: gp.is_active,
    });
    try {
      const parsed: FieldDef[] = JSON.parse(gp.fields_schema || "[]");
      setFields(parsed);
    } catch {
      setFields([]);
    }
    setShowForm(true);
    setExpandedId(null);
  };

  const addField = () => setFields(prev => [...prev, { ...emptyField }]);
  const removeField = (i: number) => setFields(prev => prev.filter((_, idx) => idx !== i));
  const updateField = (i: number, patch: Partial<FieldDef>) =>
    setFields(prev => prev.map((f, idx) => idx === i ? { ...f, ...patch } : f));

  const handleSave = async () => {
    if (!form.name) { msg("❌ Name is required"); return; }
    setSaving(true);
    const body = { ...form, fields_schema: JSON.stringify(fields) };
    const res = editingId
      ? await apiFetch(`/golden-paths/${editingId}`, { method: "PUT", body: JSON.stringify(body) })
      : await apiFetch("/golden-paths", { method: "POST", body: JSON.stringify(body) });
    const data = await res.json();
    setSaving(false);
    if (res.ok) {
      msg(editingId ? "✅ Golden Path updated!" : "✅ Golden Path created!");
      setShowForm(false);
      load();
    } else {
      msg(`❌ ${data.error}`);
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Remove "${name}"?`)) return;
    await apiFetch(`/golden-paths/${id}`, { method: "DELETE" });
    msg("✅ Removed");
    load();
  };

  const toggleActive = async (gp: GoldenPath) => {
    await apiFetch(`/golden-paths/${gp.id}`, {
      method: "PUT",
      body: JSON.stringify({ is_active: !gp.is_active }),
    });
    load();
  };

  const parsedFields = (gp: GoldenPath): FieldDef[] => {
    try { return JSON.parse(gp.fields_schema || "[]"); } catch { return []; }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold">
            Golden Paths
          </h1>
          <p className="text-zinc-400 mt-1 text-sm">
            Templates with guardrails. Define required fields, validations, and approval workflows for repository creation.
          </p>
        </div>
        {isAdmin && (
          <button onClick={openCreate} className="btn-primary text-sm px-4 py-2 shrink-0">
            + New Golden Path
          </button>
        )}
      </header>

      {message && (
        <div className={`p-3 rounded border text-sm ${message.startsWith("✅") ? "bg-brand-green/10 border-brand-green/40 text-brand-green" : "bg-red-500/10 border-red-500/40 text-red-400"}`}>
          {message}
        </div>
      )}

      {/* Form */}
      {showForm && isAdmin && (
        <div className="glass-card p-6 border-l-4 border-l-brand-gold space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold">{editingId ? "Edit" : "New"} Golden Path</h2>
            <button onClick={() => setShowForm(false)} className="text-zinc-500 hover:text-white text-xl">✕</button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Name *</label>
              <input className="input-tech text-sm" placeholder="e.g. Standard REST API" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Approval workflow</label>
              <select
                className="input-tech text-sm"
                value={form.approval_workflow}
                onChange={e => setForm({ ...form, approval_workflow: e.target.value as "none" | "manual" })}
              >
                <option value="none">Automatic (no approval needed)</option>
                <option value="manual">Manual (admin must approve)</option>
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="text-xs text-zinc-400 mb-1 block">Description</label>
              <input className="input-tech text-sm" placeholder="What type of project is this path intended for?" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Allowed namespaces <span className="text-zinc-600">(comma-separated)</span></label>
              <input className="input-tech text-sm" placeholder="production, staging" value={form.allowed_namespaces} onChange={e => setForm({ ...form, allowed_namespaces: e.target.value })} />
            </div>
            <div className="flex items-center gap-3 pt-5">
              <input
                type="checkbox"
                id="is_active"
                className="accent-brand-green w-4 h-4"
                checked={form.is_active}
                onChange={e => setForm({ ...form, is_active: e.target.checked })}
              />
              <label htmlFor="is_active" className="text-sm text-zinc-300 cursor-pointer">Active (available for selection)</label>
            </div>
          </div>

          {/* Fields schema */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-bold text-zinc-200">Custom fields</h3>
                <p className="text-xs text-zinc-500">Fields that developers fill in when creating a repository with this path. Use <code className="text-brand-green">{"{{.Inputs.key}}"}</code> in templates.</p>
              </div>
              <button onClick={addField} className="btn-secondary text-xs px-3 py-1.5">+ Add field</button>
            </div>

            {fields.length === 0 && (
              <p className="text-zinc-600 text-sm text-center py-4 border border-dashed border-zinc-800 rounded-lg">
                No fields defined. Click &quot;+ Add field&quot; to add one.
              </p>
            )}

            <div className="space-y-3">
              {fields.map((f, i) => (
                <div key={i} className="bg-zinc-900/50 rounded-lg p-4 border border-zinc-800 space-y-3">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div>
                      <label className="text-xs text-zinc-500 mb-1 block">Key</label>
                      <input
                        className="input-tech text-xs"
                        placeholder="team_name"
                        value={f.key}
                        onChange={e => updateField(i, { key: e.target.value })}
                      />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-500 mb-1 block">Label</label>
                      <input
                        className="input-tech text-xs"
                        placeholder="Team name"
                        value={f.label}
                        onChange={e => updateField(i, { label: e.target.value })}
                      />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-500 mb-1 block">Type</label>
                      <select
                        className="input-tech text-xs"
                        value={f.type}
                        onChange={e => updateField(i, { type: e.target.value as FieldDef["type"] })}
                      >
                        <option value="string">Text</option>
                        <option value="number">Number</option>
                        <option value="select">Select</option>
                        <option value="bool">Yes/No</option>
                      </select>
                    </div>
                    <div className="flex items-end gap-2">
                      <label className="flex items-center gap-2 cursor-pointer pb-2">
                        <input
                          type="checkbox"
                          className="accent-brand-green"
                          checked={f.required}
                          onChange={e => updateField(i, { required: e.target.checked })}
                        />
                        <span className="text-xs text-zinc-400">Required</span>
                      </label>
                      <button
                        onClick={() => removeField(i)}
                        className="ml-auto text-red-500 hover:text-red-400 text-sm pb-1"
                        title="Remove field"
                      >✕</button>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-zinc-500 mb-1 block">Default value</label>
                      <input
                        className="input-tech text-xs"
                        placeholder="(optional)"
                        value={f.default || ""}
                        onChange={e => updateField(i, { default: e.target.value })}
                      />
                    </div>
                    {f.type === "select" ? (
                      <div>
                        <label className="text-xs text-zinc-500 mb-1 block">Options <span className="text-zinc-600">(comma-separated)</span></label>
                        <input
                          className="input-tech text-xs"
                          placeholder="option1, option2, option3"
                          value={(f.options || []).join(", ")}
                          onChange={e => updateField(i, { options: e.target.value.split(",").map(s => s.trim()).filter(Boolean) })}
                        />
                      </div>
                    ) : (
                      <div>
                        <label className="text-xs text-zinc-500 mb-1 block">Validation <span className="text-zinc-600">(optional regex)</span></label>
                        <input
                          className="input-tech text-xs font-mono"
                          placeholder="^[a-z][a-z0-9-]+$"
                          value={f.validation || ""}
                          onChange={e => updateField(i, { validation: e.target.value })}
                        />
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-3">
            <button onClick={() => setShowForm(false)} className="btn-secondary text-sm px-4 py-2">Cancel</button>
            <button onClick={handleSave} disabled={saving} className="btn-primary text-sm px-5 py-2 disabled:opacity-50">
              {saving ? "Saving..." : editingId ? "Save changes" : "Create Golden Path"}
            </button>
          </div>
        </div>
      )}

      {/* List */}
      {loading ? (
        <div className="text-zinc-500 text-center py-16">Loading...</div>
      ) : paths.length === 0 ? (
        <div className="glass-card p-12 text-center">
          <div className="text-5xl mb-4">🛤️</div>
          <h3 className="text-lg font-bold text-zinc-300 mb-2">No Golden Paths configured</h3>
          <p className="text-zinc-500 text-sm mb-6">Golden Paths define standardized templates with validations for repository creation.</p>
          {isAdmin && (
            <button onClick={openCreate} className="btn-primary text-sm px-5 py-2">Create first Golden Path</button>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          {paths.map(gp => {
            const gpFields = parsedFields(gp);
            const isExpanded = expandedId === gp.id;
            return (
              <div key={gp.id} className={`glass-card border-l-4 transition-colors ${gp.is_active ? "border-l-brand-green" : "border-l-zinc-700"}`}>
                <div className="p-5 flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 flex-wrap">
                      <h3 className="font-bold text-base">{gp.name}</h3>
                      <span className={`text-xs px-2 py-0.5 rounded border ${gp.is_active ? "text-brand-green border-brand-green/40 bg-brand-green/10" : "text-zinc-500 border-zinc-700 bg-zinc-800/50"}`}>
                        {gp.is_active ? "Active" : "Inactive"}
                      </span>
                      <span className={`text-xs px-2 py-0.5 rounded border ${gp.approval_workflow === "manual" ? "text-yellow-400 border-yellow-500/40 bg-yellow-500/10" : "text-zinc-400 border-zinc-700"}`}>
                        {gp.approval_workflow === "manual" ? "Manual approval" : "Automatic"}
                      </span>
                    </div>
                    {gp.description && <p className="text-zinc-400 text-sm mt-1">{gp.description}</p>}
                    <div className="flex items-center gap-4 mt-2 text-xs text-zinc-500">
                      <span>{gpFields.length} field{gpFields.length !== 1 ? "s" : ""}</span>
                      {gp.allowed_namespaces && <span>Namespaces: {gp.allowed_namespaces}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : gp.id)}
                      className="text-xs text-zinc-400 hover:text-white border border-zinc-700 hover:border-zinc-500 px-3 py-1.5 rounded transition"
                    >
                      {isExpanded ? "Close" : "Details"}
                    </button>
                    {isAdmin && (
                      <>
                        <button onClick={() => openEdit(gp)} className="btn-secondary text-xs px-3 py-1.5">Edit</button>
                        <button
                          onClick={() => toggleActive(gp)}
                          className={`text-xs px-3 py-1.5 rounded border transition ${gp.is_active ? "border-yellow-600/50 text-yellow-500 hover:bg-yellow-500/10" : "border-brand-green/50 text-brand-green hover:bg-brand-green/10"}`}
                        >
                          {gp.is_active ? "Deactivate" : "Activate"}
                        </button>
                        <button onClick={() => handleDelete(gp.id, gp.name)} className="text-xs text-red-500 hover:text-red-400 border border-red-500/30 hover:border-red-500/60 px-3 py-1.5 rounded transition">Remove</button>
                      </>
                    )}
                  </div>
                </div>

                {isExpanded && gpFields.length > 0 && (
                  <div className="border-t border-zinc-800 px-5 pb-5 pt-4">
                    <h4 className="text-xs text-zinc-500 uppercase tracking-wider mb-3">Fields</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {gpFields.map((f, i) => (
                        <div key={i} className="bg-zinc-900/60 rounded-lg p-3 border border-zinc-800">
                          <div className="flex items-center justify-between mb-1">
                            <code className="text-brand-green text-xs font-mono">{f.key}</code>
                            <div className="flex gap-1">
                              {f.required && <span className="text-xs text-red-400 border border-red-500/30 px-1.5 rounded">required</span>}
                              <span className="text-xs text-zinc-500 border border-zinc-700 px-1.5 rounded">{f.type}</span>
                            </div>
                          </div>
                          <p className="text-zinc-300 text-sm">{f.label}</p>
                          {f.default && <p className="text-zinc-600 text-xs mt-1">default: {f.default}</p>}
                          {f.options && f.options.length > 0 && (
                            <p className="text-zinc-600 text-xs mt-1">options: {f.options.join(", ")}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {isExpanded && gpFields.length === 0 && (
                  <div className="border-t border-zinc-800 px-5 pb-4 pt-3">
                    <p className="text-zinc-600 text-sm">This Golden Path has no custom fields.</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
