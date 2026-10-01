/** Exports a repository's scan findings -- exactly the rows on screen, after
 *  the severity filter and the search -- as a spreadsheet or a printable
 *  report. Everything happens in the browser: the findings are already
 *  loaded, and a server round trip would only add a second copy of the
 *  formatting rules. */

export interface ExportFinding {
  target: string;
  type: string;
  vuln_id: string;
  pkg: string;
  version: string;
  fixed: string;
  severity: string;
  title: string;
}

export interface ExportContext {
  repo: string;
  kind: "code" | "image";
  scannedAt: string;
  image?: string;
  /** Severity filter and search text, so the reader knows what was left out. */
  severityFilter: string;
  search: string;
  /** Size of the unfiltered list. */
  total: number;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

const kindLabel = (k: ExportContext["kind"]) => (k === "image" ? "Image scan" : "Code scan");

const referenceURL = (f: ExportFinding) =>
  f.type === "vulnerability" && /^(CVE|GHSA)-/i.test(f.vuln_id)
    ? f.vuln_id.toUpperCase().startsWith("GHSA")
      ? `https://github.com/advisories/${f.vuln_id}`
      : `https://nvd.nist.gov/vuln/detail/${f.vuln_id}`
    : "";

function fileStem(ctx: ExportContext) {
  const day = new Date().toISOString().slice(0, 10);
  return `${ctx.repo}-${ctx.kind}-findings-${day}`.replace(/[^\w.-]+/g, "_");
}

function download(name: string, body: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function filterSummary(ctx: ExportContext, shown: number) {
  const parts = [];
  if (ctx.severityFilter && ctx.severityFilter !== "ALL") parts.push(`severity ${ctx.severityFilter}`);
  if (ctx.search.trim()) parts.push(`search "${ctx.search.trim()}"`);
  return parts.length
    ? `${shown} of ${ctx.total} findings (filtered by ${parts.join(", ")})`
    : `${shown} findings`;
}

function countBySeverity(findings: ExportFinding[]) {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    const s = (f.severity || "UNKNOWN").toUpperCase();
    counts[s] = (counts[s] ?? 0) + 1;
  }
  return counts;
}

/** CSV with a UTF-8 BOM and ";" as separator: that is what Excel expects in
 *  a pt-BR locale, where "," is the decimal mark -- with "," every row would
 *  land in column A. Google Sheets and LibreOffice detect either. */
export function exportFindingsCSV(findings: ExportFinding[], ctx: ExportContext) {
  const cell = (v: string) => {
    const s = (v ?? "").replace(/\r?\n/g, " ");
    // Leading = + - @ would be read as a formula by a spreadsheet.
    const safe = /^[=+\-@]/.test(s) ? `'${s}` : s;
    return /[";]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  const header = ["Severity", "ID", "Type", "Title", "Target", "Package", "Installed", "Fixed in", "Reference"];
  const lines = [header.join(";")];
  for (const f of findings) {
    lines.push([
      f.severity, f.vuln_id, f.type, f.title, f.target, f.pkg, f.version, f.fixed, referenceURL(f),
    ].map(cell).join(";"));
  }
  download(`${fileStem(ctx)}.csv`, "﻿" + lines.join("\r\n") + "\r\n", "text/csv;charset=utf-8");
}

const esc = (s: string) =>
  (s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

/** A self-contained report printed from a hidden iframe, so the browser's own
 *  "Save as PDF" produces the document -- no PDF library, no pop-up window. */
export function exportFindingsPDF(findings: ExportFinding[], ctx: ExportContext) {
  const counts = countBySeverity(findings);
  const generated = new Date().toLocaleString();
  const scanned = ctx.scannedAt ? new Date(ctx.scannedAt).toLocaleString() : "—";
  const rows = findings.map(f => {
    const url = referenceURL(f);
    const id = url ? `<a href="${esc(url)}">${esc(f.vuln_id)}</a>` : esc(f.vuln_id);
    return `<tr>
      <td class="sev ${esc((f.severity || "").toLowerCase())}">${esc(f.severity)}</td>
      <td class="mono">${id}</td>
      <td>${esc(f.title)}</td>
      <td class="mono">${esc(f.pkg || "—")}${f.version ? `<br><span class="muted">${esc(f.version)}</span>` : ""}</td>
      <td class="mono fixed">${esc(f.fixed || "—")}</td>
      <td class="mono muted target">${esc(f.target)}</td>
    </tr>`;
  }).join("");

  const html = `<!doctype html><html><head><meta charset="utf-8">
<title>${esc(fileStem(ctx))}</title>
<style>
  @page { size: A4 landscape; margin: 12mm; }
  /* A document for paper: light whatever the app's theme is. */
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  html, body { background: #fff; }
  body { font: 11px/1.4 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #18181b; margin: 0; }
  h1 { font-size: 18px; margin: 0 0 2px; }
  .muted { color: #71717a; }
  .meta { margin: 8px 0 12px; display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; }
  .meta dt { color: #71717a; } .meta dd { margin: 0; word-break: break-all; }
  .counts { display: flex; gap: 8px; margin-bottom: 12px; }
  .counts div { border: 1px solid #e4e4e7; border-radius: 6px; padding: 4px 10px; min-width: 72px; }
  .counts b { display: block; font-size: 15px; }
  table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: inherit; }
  th { text-align: left; font-weight: 600; color: #52525b; border-bottom: 1.5px solid #a1a1aa; padding: 5px 6px; }
  td { border-bottom: 1px solid #e4e4e7; padding: 4px 6px; vertical-align: top; word-wrap: break-word; }
  tr { page-break-inside: avoid; }
  thead { display: table-header-group; }
  .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 10px; }
  .sev { font-weight: 700; font-size: 10px; }
  .critical { color: #b91c1c; } .high { color: #c2410c; } .medium { color: #a16207; } .low { color: #15803d; }
  .fixed { color: #15803d; } .target { font-size: 9px; }
  a { color: #1d4ed8; text-decoration: none; }
  footer { margin-top: 10px; color: #a1a1aa; font-size: 9px; }
</style></head><body>
  <h1>${esc(ctx.repo)} — ${kindLabel(ctx.kind)}</h1>
  <div class="muted">${esc(filterSummary(ctx, findings.length))}</div>
  <dl class="meta">
    <dt>Scanned</dt><dd>${esc(scanned)}</dd>
    ${ctx.image ? `<dt>Image</dt><dd class="mono">${esc(ctx.image)}</dd>` : ""}
    <dt>Generated</dt><dd>${esc(generated)}</dd>
  </dl>
  <div class="counts">
    ${SEVERITIES.filter(s => counts[s]).map(s => `<div><b class="${s.toLowerCase()}">${counts[s]}</b>${s}</div>`).join("")}
  </div>
  <table>
    <colgroup><col style="width:8%"><col style="width:13%"><col style="width:33%"><col style="width:15%"><col style="width:12%"><col style="width:19%"></colgroup>
    <thead><tr><th>Severity</th><th>ID</th><th>Title</th><th>Package</th><th>Fixed in</th><th>Target</th></tr></thead>
    <tbody>${rows || `<tr><td colspan="6" class="muted">No findings.</td></tr>`}</tbody>
  </table>
  <footer>Generated by CommitKube · scanner: Trivy</footer>
</body></html>`;

  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;";
  document.body.appendChild(frame);
  const doc = frame.contentDocument;
  if (!doc) { frame.remove(); return; }
  doc.open();
  doc.write(html);
  doc.close();
  // Print once the report has laid out; remove the frame after the dialog.
  setTimeout(() => {
    frame.contentWindow?.focus();
    frame.contentWindow?.print();
    setTimeout(() => frame.remove(), 1000);
  }, 250);
}
