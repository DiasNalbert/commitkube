"use client";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface Workspace {
  id: number;
  alias: string;
  workspace_id: string;
  project_key: string;
}

export interface WorkspaceSelection {
  slug: string;
  project_key: string;
  label: string;
}

interface Props {
  value: WorkspaceSelection | null;
  onChange: (sel: WorkspaceSelection | null) => void;
}

export default function WorkspaceFilter({ value, onChange }: Props) {
  const [options, setOptions] = useState<WorkspaceSelection[]>([]);

  useEffect(() => {
    apiFetch("/workspaces").then(r => r.json()).then((wsList: Workspace[]) => {
      if (!Array.isArray(wsList)) return;
      const seen = new Set<string>();
      const deduped: WorkspaceSelection[] = [];
      for (const ws of wsList) {
        const key = `${ws.workspace_id}||${ws.project_key}`;
        if (!seen.has(key)) {
          seen.add(key);
          deduped.push({
            slug: ws.workspace_id,
            project_key: ws.project_key,
            label: ws.alias,
          });
        }
      }
      setOptions(deduped);
    }).catch(() => {});
  }, []);

  if (options.length === 0) return null;

  const isSelected = (opt: WorkspaceSelection) =>
    value?.slug === opt.slug && value?.project_key === opt.project_key;

  return (
    <div className="flex items-center gap-2 flex-wrap mb-4">
      <span className="text-xs text-zinc-500 uppercase tracking-wide font-medium">Filtro:</span>
      <button
        onClick={() => onChange(null)}
        className={`px-3 py-1 text-sm rounded-full border transition-colors ${
          value === null
            ? "bg-brand-green border-brand-green text-black"
            : "border-zinc-600 text-zinc-400 hover:bg-zinc-800"
        }`}
      >
        All
      </button>
      {options.map(opt => (
        <button
          key={`${opt.slug}||${opt.project_key}`}
          onClick={() => onChange(isSelected(opt) ? null : opt)}
          className={`flex items-center gap-1.5 px-3 py-1 text-sm rounded-full border transition-colors ${
            isSelected(opt)
              ? "bg-brand-green border-brand-green text-black"
              : "border-zinc-600 text-zinc-400 hover:bg-zinc-800"
          }`}
        >
          <span>{opt.label}</span>
          {opt.project_key && (
            <span className={`text-xs px-1.5 py-0.5 rounded ${isSelected(opt) ? "bg-black/20 text-black/70" : "bg-zinc-700/50 text-zinc-400"}`}>
              project: {opt.project_key}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}
