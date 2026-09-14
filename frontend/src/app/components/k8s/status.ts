/** Shared vocabulary for the Kubernetes browser: the row shape every resource
 *  list returns, and the four health states they are rendered in. Kept apart
 *  from the components so the list and the detail panel can both use it without
 *  importing each other. */

export interface ResourceRow {
  name: string;
  namespace: string;
  age: string;
  status: string;
  status_text: string;
  fields: Record<string, string>;
}

export interface ResourceColumn {
  /** "name" | "namespace" | "age" | "status" | any key of row.fields */
  id: string;
  label: string;
  align?: "left" | "right";
  mono?: boolean;
  truncate?: boolean;
  width?: string;
}

export const STATUS_STYLES: Record<string, { dot: string; text: string; border: string; bg: string }> = {
  critical: { dot: "bg-red-500",   text: "text-red-500 dark:text-red-400",     border: "border-red-500/30",   bg: "bg-red-500/10" },
  warning:  { dot: "bg-amber-500", text: "text-amber-600 dark:text-amber-400", border: "border-amber-500/30", bg: "bg-amber-500/10" },
  healthy:  { dot: "bg-brand-green", text: "text-brand-green",                 border: "border-brand-green/30", bg: "bg-brand-green/10" },
  unknown:  { dot: "bg-zinc-400 dark:bg-zinc-600", text: "text-zinc-500 dark:text-zinc-400", border: "border-zinc-500/30", bg: "bg-zinc-500/10" },
};

export const statusStyle = (s: string) => STATUS_STYLES[s] ?? STATUS_STYLES.unknown;
