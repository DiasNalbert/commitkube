"use client";
import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface Workspace {
  id: number;
  alias: string;
  workspace_id: string;
  project_key: string;
}

interface Props {
  value: number | null;
  onChange: (workspaceId: number | null) => void;
}

export default function WorkspaceFilter({ value, onChange }: Props) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);

  useEffect(() => {
    apiFetch("/workspaces").then(r => r.json()).then(setWorkspaces).catch(() => {});
  }, []);

  if (workspaces.length === 0) return null;

  return (
    <div className="flex items-center gap-2 flex-wrap mb-4">
      <span className="text-xs text-zinc-500 dark:text-zinc-500 uppercase tracking-wide font-medium">Filtro:</span>
      {[{ id: 0, alias: "All", workspace_id: "", project_key: "" }, ...workspaces].map(ws => (
        <button
          key={ws.id}
          onClick={() => onChange(ws.id === 0 ? null : ws.id)}
          className={`flex items-center gap-1.5 px-3 py-1 text-sm rounded-full border transition-colors ${
            (ws.id === 0 && value === null) || value === ws.id
              ? "bg-brand-green border-brand-green text-black dark:text-black"
              : "border-zinc-300 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800"
          }`}
        >
          {ws.id === 0 ? "All" : (
            <>
              <span>{ws.alias}</span>
              {ws.project_key && (
                <span className={`text-xs px-1.5 py-0.5 rounded ${(value === ws.id) ? "bg-black/20 text-black/70" : "bg-zinc-700/50 text-zinc-400"}`}>
                  project: {ws.project_key}
                </span>
              )}
            </>
          )}
        </button>
      ))}
    </div>
  );
}
