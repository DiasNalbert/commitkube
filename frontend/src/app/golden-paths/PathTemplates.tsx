"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

export type FieldDef = {
  key: string;
  label: string;
  type: "string" | "number" | "select" | "bool";
  required: boolean;
  options?: string[];
  validation?: string;
  default?: string;
};

type Template = { id: number; name: string; path: string; content: string; type: string; is_active: boolean };
type Preview = { files: Record<string, string>; namespace?: string; violations: string[]; error?: string };

const STARTER = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    app: {{.Name}}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: {{.Name}}
  template:
    metadata:
      labels:
        app: {{.Name}}
    spec:
      containers:
        - name: {{.Name}}
          image: registry.example.com/{{.Name}}:latest
          ports:
            - containerPort: 8080
          resources:
            limits:
              cpu: 500m
              memory: 512Mi
`;

/** The help a template author needs, next to the editor rather than in a
 *  wiki nobody opens. */
function Cheatsheet({ fields }: { fields: FieldDef[] }) {
  return (
    <div className="text-[12px] leading-relaxed" style={{ color: "var(--t3)" }}>
      <p className="m-0 mb-1">Available in these templates:</p>
      <ul className="m-0 pl-4 space-y-0.5 font-mono text-[11.5px]">
        <li>{"{{.Name}}"} <span className="font-sans">— repository name</span></li>
        <li>{"{{.Namespace}}"} <span className="font-sans">— the namespace chosen from the allowed list</span></li>
        <li>{"{{.Limits.cpu}}"}, {"{{.Limits.memory}}"} <span className="font-sans">— this path&apos;s ceiling</span></li>
        {fields.filter(f => f.key).map(f => (
          <li key={f.key}>
            {f.type === "bool" ? `{{if .Inputs.${f.key}}} … {{end}}` : `{{.Inputs.${f.key}}}`}
            <span className="font-sans"> — {f.label || f.key}{f.type === "bool" ? " (yes/no)" : ""}</span>
          </li>
        ))}
      </ul>
      <p className="m-0 mt-1.5">
        Helpers: <code>lower</code>, <code>upper</code>, <code>quote</code>, <code>default</code>.
        A literal <code>{"{{"}</code> (Helm, GitHub Actions) is written <code>{'{{"{{"}}'}</code>.
      </p>
    </div>
  );
}

function TemplateEditor({ t, fields, onSaved, onCancel, goldenPathId }: {
  t: Template | null; fields: FieldDef[]; goldenPathId: number;
  onSaved: () => void; onCancel: () => void;
}) {
  const [name, setName] = useState(t?.name ?? "deployment.yaml");
  const [path, setPath] = useState(t?.path ?? "k8s");
  const [type, setType] = useState(t?.type ?? "manifest");
  const [content, setContent] = useState(t?.content ?? STARTER);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    setError("");
    const res = t
      ? await apiFetch(`/templates/${t.id}`, { method: "PUT", body: JSON.stringify({ name, path, type, content }) })
      : await apiFetch("/templates", { method: "POST", body: JSON.stringify({ name, path, type, content, golden_path_id: goldenPathId }) });
    const body = await res.json().catch(() => ({}));
    setBusy(false);
    if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
    onSaved();
  };

  return (
    <div className="flex flex-col gap-3 p-4" style={{ background: "var(--panel)", border: "1px solid var(--rule)" }}>
      <div className="grid gap-3" style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr) 140px" }}>
        <label className="flex flex-col gap-1 text-xs" style={{ color: "var(--t3)" }}>File name
          <input className="input-tech text-sm font-mono" value={name} onChange={e => setName(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 text-xs" style={{ color: "var(--t3)" }}>Folder
          <input className="input-tech text-sm font-mono" value={path} placeholder="(repository root)" onChange={e => setPath(e.target.value)} />
        </label>
        <label className="flex flex-col gap-1 text-xs" style={{ color: "var(--t3)" }}>Kind
          <select className="input-tech text-sm" value={type} onChange={e => setType(e.target.value)}>
            <option value="manifest">Manifest</option>
            <option value="pipeline">Pipeline</option>
            <option value="file">Other file</option>
          </select>
        </label>
      </div>
      <div className="grid gap-4" style={{ gridTemplateColumns: "minmax(0,1fr) 280px" }}>
        <textarea
          className="w-full font-mono text-xs p-3 rounded"
          style={{ background: "var(--input)", color: "var(--text)", border: "1px solid var(--line)", minHeight: 320 }}
          value={content}
          onChange={e => setContent(e.target.value)}
          spellCheck={false}
        />
        <Cheatsheet fields={fields} />
      </div>
      {error && <p className="m-0 text-xs whitespace-pre-wrap" style={{ color: "var(--red)" }}>{error}</p>}
      <div className="flex gap-2 justify-end">
        <button type="button" onClick={onCancel} className="btn-secondary">Cancel</button>
        <button type="button" onClick={save} disabled={busy || !name} className="btn-primary disabled:opacity-50">{busy ? "Saving…" : "Save template"}</button>
      </div>
    </div>
  );
}

/** Answers for a preview: one input per field, plus the namespace. */
export function InputsForm({ fields, values, onChange, namespaces }: {
  fields: FieldDef[]; values: Record<string, string>; onChange: (v: Record<string, string>) => void; namespaces: string;
}) {
  const allowed = namespaces.split(",").map(s => s.trim()).filter(Boolean);
  const exact = allowed.filter(a => !/[*?[]/.test(a));
  const set = (k: string, v: string) => onChange({ ...values, [k]: v });
  return (
    <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(200px,1fr))" }}>
      {allowed.length > 0 && (
        <label className="flex flex-col gap-1 text-xs" style={{ color: "var(--t3)" }}>Namespace
          {allowed.length === exact.length ? (
            <select className="input-tech text-sm" value={values.namespace ?? (exact.length === 1 ? exact[0] : "")} onChange={e => set("namespace", e.target.value)}>
              {exact.length > 1 && <option value="">Choose…</option>}
              {exact.map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          ) : (
            <input className="input-tech text-sm font-mono" placeholder={allowed.join(", ")} value={values.namespace ?? ""} onChange={e => set("namespace", e.target.value)} />
          )}
        </label>
      )}
      {fields.filter(f => f.key).map(f => (
        <label key={f.key} className="flex flex-col gap-1 text-xs" style={{ color: "var(--t3)" }}>
          {f.label || f.key}{f.required ? " *" : ""}
          {f.type === "bool" ? (
            <select className="input-tech text-sm" value={values[f.key] ?? (f.default || "no")} onChange={e => set(f.key, e.target.value)}>
              <option value="no">No</option>
              <option value="yes">Yes</option>
            </select>
          ) : f.type === "select" ? (
            <select className="input-tech text-sm" value={values[f.key] ?? f.default ?? ""} onChange={e => set(f.key, e.target.value)}>
              {!f.required && <option value="">—</option>}
              {(f.options ?? []).map(o => <option key={o} value={o}>{o}</option>)}
            </select>
          ) : (
            <input
              className="input-tech text-sm"
              inputMode={f.type === "number" ? "numeric" : undefined}
              placeholder={f.default || ""}
              value={values[f.key] ?? ""}
              onChange={e => set(f.key, e.target.value)}
            />
          )}
        </label>
      ))}
    </div>
  );
}

/** A golden path's own files: what a repository created on it receives, on
 *  top of the project's templates, and a preview of the result. */
export default function PathTemplates({ goldenPathId, fields, namespaces, canEdit }: {
  goldenPathId: number; fields: FieldDef[]; namespaces: string; canEdit: boolean;
}) {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [editing, setEditing] = useState<Template | null | "new">(null);
  const [sample, setSample] = useState<Record<string, string>>({});
  const [repoName, setRepoName] = useState("orders-api");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [previewing, setPreviewing] = useState(false);

  const load = useCallback(async () => {
    const res = await apiFetch(`/templates?golden_path_id=${goldenPathId}`);
    const data = await res.json().catch(() => []);
    setTemplates(Array.isArray(data) ? data : []);
  }, [goldenPathId]);
  useEffect(() => { load(); }, [load]);

  const remove = async (t: Template) => {
    if (!confirm(`Remove ${t.path ? t.path + "/" : ""}${t.name} from this golden path?`)) return;
    await apiFetch(`/templates/${t.id}`, { method: "DELETE" });
    load();
  };

  const runPreview = async () => {
    setPreviewing(true);
    const res = await apiFetch(`/golden-paths/${goldenPathId}/preview`, {
      method: "POST", body: JSON.stringify({ name: repoName, inputs: sample }),
    });
    setPreview(await res.json().catch(() => ({ files: {}, violations: [], error: `Request failed (${res.status})` })));
    setPreviewing(false);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-baseline justify-between gap-3">
        <div>
          <h4 className="m-0 text-sm font-semibold">Files this path creates</h4>
          <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>
            Committed to every repository created on this path, over the project&apos;s templates where both write the same file.
          </p>
        </div>
        {canEdit && editing === null && <button type="button" onClick={() => setEditing("new")} className="btn-secondary shrink-0">Add file</button>}
      </div>

      {templates.length === 0 && editing === null && (
        <p className="m-0 text-sm py-3" style={{ color: "var(--t3)", borderTop: "1px solid var(--rule2)" }}>
          No files yet: a repository on this path gets only the project&apos;s templates.
        </p>
      )}
      {templates.map(t => editing !== null && editing !== "new" && editing.id === t.id ? (
        <TemplateEditor key={t.id} t={t} fields={fields} goldenPathId={goldenPathId}
          onSaved={() => { setEditing(null); load(); }} onCancel={() => setEditing(null)} />
      ) : (
        <div key={t.id} className="flex items-center gap-3 py-2" style={{ borderTop: "1px solid var(--rule2)" }}>
          <span className="font-mono text-[12.5px] flex-1">{t.path ? `${t.path}/` : ""}<strong>{t.name}</strong></span>
          <span className="text-[11px]" style={{ color: "var(--m2)" }}>{t.type}</span>
          {canEdit && (
            <>
              <button type="button" onClick={() => setEditing(t)} className="text-[12.5px] p-0" style={{ color: "var(--green)" }}>Edit</button>
              <button type="button" onClick={() => remove(t)} className="text-[12.5px] p-0" style={{ color: "var(--red)" }}>Remove</button>
            </>
          )}
        </div>
      ))}
      {editing === "new" && (
        <TemplateEditor t={null} fields={fields} goldenPathId={goldenPathId}
          onSaved={() => { setEditing(null); load(); }} onCancel={() => setEditing(null)} />
      )}

      {templates.length > 0 && (
        <div className="flex flex-col gap-3 pt-3" style={{ borderTop: "1px solid var(--rule)" }}>
          <h4 className="m-0 text-sm font-semibold">Preview</h4>
          <label className="flex flex-col gap-1 text-xs max-w-[260px]" style={{ color: "var(--t3)" }}>Repository name
            <input className="input-tech text-sm font-mono" value={repoName} onChange={e => setRepoName(e.target.value)} />
          </label>
          <InputsForm fields={fields} values={sample} onChange={setSample} namespaces={namespaces} />
          <button type="button" onClick={runPreview} disabled={previewing} className="btn-secondary self-start">{previewing ? "Rendering…" : "Render"}</button>
          {preview?.error && <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{preview.error}</p>}
          {preview && preview.violations.length > 0 && (
            <div className="p-3 text-xs flex flex-col gap-1" style={{ border: "1px solid rgba(248,113,113,.3)", color: "var(--red)" }}>
              <strong>This would be refused:</strong>
              {preview.violations.map(v => <span key={v}>{v}</span>)}
            </div>
          )}
          {preview && !preview.error && preview.violations.length === 0 && Object.keys(preview.files).length > 0 && (
            <p className="m-0 text-xs" style={{ color: "var(--green)" }}>Passes this path&apos;s rules{preview.namespace ? ` · namespace ${preview.namespace}` : ""}.</p>
          )}
          {preview && Object.entries(preview.files).map(([f, c]) => (
            <div key={f} className="flex flex-col gap-1">
              <span className="font-mono text-[11.5px]" style={{ color: "var(--t3)" }}>{f}</span>
              <pre className="m-0 p-3 font-mono text-[11px] overflow-x-auto" style={{ background: "var(--side)", border: "1px solid var(--rule)" }}>{c}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
