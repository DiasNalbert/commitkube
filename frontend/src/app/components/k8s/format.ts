/** Number formatting shared by the Kubernetes pages, so a value reads the same
 *  in the overview, in a detail panel and in a table. */

/** CPU in the unit the value deserves: millicores below one core, cores above. */
export const fmtCores = (cores: number) =>
  !cores ? "0" : cores < 1 ? `${Math.round(cores * 1000)} mcore` : `${cores.toFixed(cores < 10 ? 2 : 1)} core`;

export const fmtBytes = (bytes: number) => {
  if (!bytes) return "0";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
};

/** Utilization reads as a state, not just a number: the colour is always paired
 *  with the percentage in text, never used as the only signal. */
export const loadStatus = (pct: number) =>
  pct >= 90 ? "critical" : pct >= 75 ? "warning" : "healthy";
