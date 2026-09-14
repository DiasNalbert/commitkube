"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { apiFetch } from "@/lib/api";

interface DirEntry {
  type: "commit_file" | "commit_directory";
  path: string;
  size?: number;
}

interface Pipeline {
  uuid: string;
  build_number: number;
  created_on: string;
  state: {
    name: string;
    result?: { name: string };
  };
  target?: { ref_name?: string };
}

interface PipelineStep {
  uuid: string;
  name: string;
  state: { name: string; result?: { name: string } };
}

export default function RepositoryDetail() {
  const params = useParams();
  const repoName = params.name as string;

  const [tab, setTab] = useState<"files" | "pipelines" | "vulnerabilities" | "commits">("files");

  interface CommitInfo {
    hash: string;
    short_hash: string;
    message: string;
    author: string;
    date: string;
  }
  const [commits, setCommits] = useState<CommitInfo[]>([]);
  const [commitsLoading, setCommitsLoading] = useState(false);
  const [commitsBranch, setCommitsBranch] = useState("main");

  const loadCommits = async (branch = commitsBranch) => {
    setCommitsLoading(true);
    try {
      const res = await apiFetch(`/repositories/${repoName}/commits?branch=${encodeURIComponent(branch)}&limit=20`);
      if (res.ok) {
        const data = await res.json();
        setCommits(data.commits ?? []);
      }
    } catch {}
    setCommitsLoading(false);
  };

  interface Finding {
    target: string; type: string; vuln_id: string; pkg: string;
    version: string; fixed: string; severity: string; title: string;
  }
  interface VulnDetail {
    repo_name: string; scanned_at: string;
    critical: number; high: number; medium: number; low: number;
    findings: Finding[];
    scanned_image: string;
    image_critical: number; image_high: number; image_medium: number; image_low: number;
    image_error: string;
    image_findings: Finding[];
  }
  const [vulnDetail, setVulnDetail] = useState<VulnDetail | null>(null);
  const [vulnTab, setVulnTab] = useState<"code" | "image">("code");
  const [vulnLoading, setVulnLoading] = useState(false);
  const [vulnSevFilter, setVulnSevFilter] = useState("ALL");
  const [vulnSearch, setVulnSearch] = useState("");

  const [currentPath, setCurrentPath] = useState("");
  const [dirEntries, setDirEntries] = useState<DirEntry[] | null>(null);
  const [fileContent, setFileContent] = useState<string | null>(null);
  const [filesLoading, setFilesLoading] = useState(false);
  const [pathHistory, setPathHistory] = useState<string[]>([]);
  const [branches, setBranches] = useState<string[]>([]);
  const [selectedBranch, setSelectedBranch] = useState("");

  const [editing, setEditing] = useState(false);
  const [editContent, setEditContent] = useState("");
  const [commitMessage, setCommitMessage] = useState("");
  const [commitBranch, setCommitBranch] = useState("main");
  const [committing, setCommitting] = useState(false);
  const [commitError, setCommitError] = useState("");
  const [commitSuccess, setCommitSuccess] = useState("");

  const [stagedFiles, setStagedFiles] = useState<{ path: string; content: string }[]>([]);
  const [stagedCommitMessage, setStagedCommitMessage] = useState("");
  const [stagedCommitBranch, setStagedCommitBranch] = useState("main");
  const [stagedCommitting, setStagedCommitting] = useState(false);
  const [stagedError, setStagedError] = useState("");
  const [stagedSuccess, setStagedSuccess] = useState("");

  const [userHasKeys, setUserHasKeys] = useState<boolean | null>(null);

  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<{ message: string; critical: number; high: number; medium: number; low: number } | null>(null);
  const [scanError, setScanError] = useState("");

  interface AnalyzeFinding {
    severity: string;
    file?: string;
    line?: number;
    title: string;
    description: string;
    snippet?: string;
    fix?: string;
  }
  interface AnalyzeResult { security: AnalyzeFinding[]; performance: AnalyzeFinding[]; best_practices: AnalyzeFinding[]; }
  const [analyzing, setAnalyzing] = useState(false);
  const [analyzeResult, setAnalyzeResult] = useState<AnalyzeResult | null>(null);
  const [analyzeError, setAnalyzeError] = useState("");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [highlightLine, setHighlightLine] = useState<number | null>(null);

  const runAnalyze = async () => {
    setAnalyzing(true);
    setAnalyzeResult(null);
    setAnalyzeError("");
    try {
      const res = await apiFetch(`/repositories/${repoName}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ branch: selectedBranch }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Analysis failed");
      setAnalyzeResult(data);
    } catch (err: any) {
      setAnalyzeError(err.message);
    } finally {
      setAnalyzing(false);
    }
  };

  const openInEditor = (file: string, line?: number) => {
    setHighlightLine(line ?? null);
    setTab("files");
    setPathHistory([]);
    setCurrentPath(file);
    loadSrc(file, selectedBranch);
  };

  const runScan = async () => {
    setScanning(true);
    setScanResult(null);
    setScanError("");
    try {
      const res = await apiFetch(`/repositories/${repoName}/scan`, { method: "POST" });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scan failed");
      setScanResult(data);
      const detail = await apiFetch(`/scan-dashboard/${repoName}`).then(r => r.json());
      if (detail.findings) setVulnDetail(detail);
    } catch (err: any) {
      setScanError(err.message);
    } finally {
      setScanning(false);
    }
  };

  const [pipelines, setPipelines] = useState<Pipeline[]>([]);
  const [pipelinesLoading, setPipelinesLoading] = useState(false);
  const [expandedPipeline, setExpandedPipeline] = useState<string | null>(null);
  const [steps, setSteps] = useState<Record<string, PipelineStep[]>>({});
  const [expandedStep, setExpandedStep] = useState<string | null>(null);
  const [stepLogs, setStepLogs] = useState<Record<string, string>>({});
  const [triggerBranch, setTriggerBranch] = useState("main");
  const [triggering, setTriggering] = useState(false);
  const [stoppingPipeline, setStoppingPipeline] = useState<string | null>(null);

  const loadSrc = async (path: string, branch?: string) => {
    setFilesLoading(true);
    setFileContent(null);
    setDirEntries(null);
    setEditing(false);
    setCommitError("");
    setCommitSuccess("");
    setHighlightLine(null);
    const branchParam = (branch ?? selectedBranch) ? `&branch=${encodeURIComponent(branch ?? selectedBranch)}` : "";
    try {
      const res = await apiFetch(`/repositories/${repoName}/src?path=${encodeURIComponent(path)}${branchParam}`);
      const contentType = res.headers.get("Content-Type") || "";
      if (contentType.includes("application/json")) {
        const data = await res.json();
        const entries: DirEntry[] = (data.values || []).map((v: any) => ({
          type: v.type,
          path: v.path,
          size: v.size,
        }));
        setDirEntries(entries);
      } else {
        const text = await res.text();
        setFileContent(text);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setFilesLoading(false);
    }
  };

  const navigateTo = (path: string) => {
    setPathHistory(h => [...h, currentPath]);
    setCurrentPath(path);
    loadSrc(path);
  };

  const navigateBack = () => {
    const prev = pathHistory[pathHistory.length - 1] ?? "";
    setPathHistory(h => h.slice(0, -1));
    setCurrentPath(prev);
    loadSrc(prev);
  };

  const startEditing = () => {
    setEditContent(fileContent ?? "");
    setCommitMessage("Update " + currentPath.split("/").pop());
    setCommitError("");
    setCommitSuccess("");
    setEditing(true);
  };

  const handleCommit = async () => {
    setCommitting(true);
    setCommitError("");
    setCommitSuccess("");
    try {
      const res = await apiFetch(`/repositories/${repoName}/src`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          path: currentPath,
          content: editContent,
          message: commitMessage || "Update " + currentPath.split("/").pop(),
          branch: commitBranch,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Commit failed");
      }
      setCommitSuccess("File committed successfully!");
      setFileContent(editContent);
      setEditing(false);
    } catch (err: any) {
      setCommitError(err.message);
    } finally {
      setCommitting(false);
    }
  };

  const stageFile = () => {
    setStagedFiles(prev => {
      const existing = prev.findIndex(f => f.path === currentPath);
      if (existing >= 0) {
        const updated = [...prev];
        updated[existing] = { path: currentPath, content: editContent };
        return updated;
      }
      return [...prev, { path: currentPath, content: editContent }];
    });
    if (stagedFiles.length === 0) {
      setStagedCommitBranch(commitBranch);
    }
    setEditing(false);
  };

  const removeStagedFile = (path: string) => {
    setStagedFiles(prev => prev.filter(f => f.path !== path));
  };

  const handleCommitStaged = async () => {
    setStagedCommitting(true);
    setStagedError("");
    setStagedSuccess("");
    try {
      const res = await apiFetch(`/repositories/${repoName}/src`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          files: stagedFiles,
          message: stagedCommitMessage || `Update ${stagedFiles.length} file(s)`,
          branch: stagedCommitBranch,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Commit failed");
      }
      setStagedSuccess(`${stagedFiles.length} file(s) committed successfully!`);
      setStagedFiles([]);
      setStagedCommitMessage("");
    } catch (err: any) {
      setStagedError(err.message);
    } finally {
      setStagedCommitting(false);
    }
  };

  const loadPipelines = async () => {
    setPipelinesLoading(true);
    try {
      const res = await apiFetch(`/repositories/${repoName}/pipelines`);
      const data = await res.json();
      setPipelines(data.values || []);
    } catch (e) {
      console.error(e);
    } finally {
      setPipelinesLoading(false);
    }
  };

  const triggerPipeline = async () => {
    setTriggering(true);
    try {
      await apiFetch(`/repositories/${repoName}/pipelines/trigger`, {
        method: "POST",
        body: JSON.stringify({ branch: triggerBranch }),
      });
      await loadPipelines();
    } catch (e) {
      console.error(e);
    } finally {
      setTriggering(false);
    }
  };

  const stopPipeline = async (uuid: string) => {
    setStoppingPipeline(uuid);
    try {
      await apiFetch(`/repositories/${repoName}/pipelines/${uuid}/stop`, { method: "POST" });
      await loadPipelines();
    } catch (e) {
      console.error(e);
    } finally {
      setStoppingPipeline(null);
    }
  };

  const isRunning = (p: Pipeline) => {
    const s = p.state?.name?.toUpperCase();
    return s === "IN_PROGRESS" || s === "PENDING" || s === "RUNNING";
  };

  const togglePipeline = async (uuid: string) => {
    if (expandedPipeline === uuid) {
      setExpandedPipeline(null);
      return;
    }
    setExpandedPipeline(uuid);
    if (!steps[uuid]) {
      const res = await apiFetch(`/repositories/${repoName}/pipelines/${uuid}/steps`);
      const data = await res.json();
      setSteps(s => ({ ...s, [uuid]: data.values || [] }));
    }
  };

  const toggleStepLog = async (pipelineUUID: string, stepUUID: string) => {
    const key = `${pipelineUUID}/${stepUUID}`;
    if (expandedStep === key) {
      setExpandedStep(null);
      return;
    }
    setExpandedStep(key);
    if (!stepLogs[key]) {
      const res = await apiFetch(`/repositories/${repoName}/pipelines/${pipelineUUID}/steps/${stepUUID}/log`);
      const text = await res.text();
      setStepLogs(l => ({ ...l, [key]: text }));
    }
  };

  useEffect(() => {
    if (highlightLine && fileContent) {
      const el = document.getElementById(`L${highlightLine}`);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [highlightLine, fileContent]);

  useEffect(() => {
    apiFetch("/workspaces")
      .then(r => r.json())
      .then((ws: any[]) => setUserHasKeys(Array.isArray(ws) && ws.some(w => w.has_app_pass)))
      .catch(() => setUserHasKeys(false));
  }, []);

  useEffect(() => {
    if (!repoName) return;
    apiFetch(`/repositories/${repoName}/branches`)
      .then(r => r.json())
      .then(data => {
        const names: string[] = (data.values || []).map((b: any) => b.name as string);
        setBranches(names);
      })
      .catch(() => {});
    loadSrc("");
    loadPipelines();
    const pipelineInterval = setInterval(async () => {
      const res = await apiFetch(`/repositories/${repoName}/pipelines`).catch(() => null);
      if (!res) return;
      const data = await res.json().catch(() => null);
      if (data?.values) setPipelines(data.values);
    }, 5000);
    apiFetch(`/scan-dashboard/${repoName}`)
      .then(r => r.json())
      .then(data => { if (data.findings) setVulnDetail(data); });
    return () => clearInterval(pipelineInterval);
  }, [repoName]);

  const pipelineStatus = (p: Pipeline) => {
    const result = p.state.result?.name || p.state.name;
    return result;
  };

  const statusColor = (status: string) => {
    const s = status.toUpperCase();
    if (s === "SUCCESSFUL") return "text-brand-green bg-brand-green/10 border-brand-green/30";
    if (s === "FAILED" || s === "ERROR") return "text-red-400 bg-red-500/10 border-red-500/30";
    if (s === "IN_PROGRESS" || s === "RUNNING") return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    return "text-zinc-400 bg-zinc-800 border-zinc-700";
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-4">
          <a href="/" className="text-zinc-400 hover:text-zinc-200 text-sm transition">← Dashboard</a>
          <h1 className="text-2xl font-bold text-brand-gold">{repoName}</h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={runAnalyze}
            disabled={analyzing}
            className="text-sm px-4 py-2 border border-brand-gold/50 text-brand-gold hover:bg-brand-gold/10 rounded transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {analyzing ? "Analyzing..." : "Code Analyze"}
          </button>
          <button
            onClick={runScan}
            disabled={scanning}
            className="btn-primary text-sm px-4 py-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {scanning ? "Scanning..." : "Security Scan"}
          </button>
        </div>
      </div>

      {scanError && (
        <div className="p-3 rounded border border-red-500/40 bg-red-500/10 text-red-400 text-sm">
          ❌ {scanError}
        </div>
      )}

      {scanResult && (
        <div className="glass-card p-4 border-l-4 border-l-brand-green">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div>
              <p className="text-brand-green font-medium text-sm">✅ {scanResult.message}</p>
            </div>
            <div className="flex gap-2 text-xs font-semibold">
              <span className="px-2 py-1 rounded border bg-red-100 text-red-700 border-red-300 dark:bg-red-900/40 dark:text-red-400 dark:border-red-500/40">C: {scanResult.critical}</span>
              <span className="px-2 py-1 rounded border bg-orange-100 text-orange-700 border-orange-300 dark:bg-orange-900/40 dark:text-orange-400 dark:border-orange-500/40">H: {scanResult.high}</span>
              <span className="px-2 py-1 rounded border bg-yellow-100 text-yellow-700 border-yellow-300 dark:bg-yellow-900/40 dark:text-yellow-400 dark:border-yellow-500/40">M: {scanResult.medium}</span>
              <span className="px-2 py-1 rounded border bg-green-100 text-green-700 border-green-300 dark:bg-green-900/40 dark:text-green-400 dark:border-green-500/40">L: {scanResult.low}</span>
            </div>
          </div>
        </div>
      )}

      {analyzeError && (
        <div className="p-3 rounded border border-red-500/40 bg-red-500/10 text-red-400 text-sm">
          ❌ {analyzeError}
        </div>
      )}

      {analyzeResult && (() => {
        const total = analyzeResult.security.length + analyzeResult.performance.length + analyzeResult.best_practices.length;
        const sevColor = (s: string) => {
          switch (s?.toLowerCase()) {
            case "high":   return "text-red-400 bg-red-500/10 border-red-500/30";
            case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
            default:       return "text-blue-400 bg-blue-500/10 border-blue-500/30";
          }
        };
        const FindingCard = ({ f, id }: { f: AnalyzeFinding; id: string }) => {
          const isOpen = expandedFinding === id;
          return (
            <div className="rounded border border-zinc-700 bg-zinc-900 overflow-hidden">
              <button
                className="w-full text-left p-3 hover:bg-zinc-800/60 transition flex items-start gap-2 flex-wrap"
                onClick={() => setExpandedFinding(isOpen ? null : id)}
              >
                <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase shrink-0 mt-0.5 ${sevColor(f.severity)}`}>
                  {f.severity}
                </span>
                {f.file && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-400 font-mono shrink-0">
                    {f.file}{f.line ? `:${f.line}` : ""}
                  </span>
                )}
                <span className="text-sm font-medium text-zinc-200 flex-1">{f.title}</span>
                <span className="text-zinc-500 text-xs shrink-0">{isOpen ? "▲" : "▼"}</span>
              </button>
              {isOpen && (
                <div className="border-t border-zinc-800 p-3 space-y-3">
                  <p className="text-xs text-zinc-400 leading-relaxed">{f.description}</p>
                  {f.snippet && (
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-red-400 mb-1">Current code</p>
                      <pre className="bg-red-950/30 border border-red-500/20 rounded p-3 text-xs font-mono text-red-200 overflow-auto whitespace-pre-wrap">{f.snippet}</pre>
                    </div>
                  )}
                  {f.fix && (
                    <div>
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-brand-green mb-1">Suggested fix</p>
                      <pre className="bg-green-950/30 border border-brand-green/20 rounded p-3 text-xs font-mono text-green-200 overflow-auto whitespace-pre-wrap">{f.fix}</pre>
                    </div>
                  )}
                  {f.file && (
                    <button
                      onClick={() => openInEditor(f.file!, f.line)}
                      className="text-xs px-3 py-1.5 rounded border border-brand-gold/40 text-brand-gold hover:bg-brand-gold/10 transition"
                    >
                      Open in editor {f.line ? `→ line ${f.line}` : ""}
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        };
        const Section = ({ label, icon, findings, prefix }: { label: string; icon: string; findings: AnalyzeFinding[]; prefix: string }) =>
          findings.length === 0 ? null : (
            <div>
              <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                <span>{icon}</span>{label}
                <span className="text-zinc-600 font-normal normal-case">({findings.length})</span>
              </h4>
              <div className="space-y-2">
                {findings.map((f, i) => <FindingCard key={i} f={f} id={`${prefix}-${i}`} />)}
              </div>
            </div>
          );
        return (
          <div className="glass-card p-5 space-y-4 border-l-4 border-l-brand-gold">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-brand-gold flex items-center gap-2">
                Code Analyze
                <span className="text-xs text-zinc-500 font-normal">{total} finding{total !== 1 ? "s" : ""}</span>
              </h3>
              <button onClick={() => { setAnalyzeResult(null); setExpandedFinding(null); }} className="text-xs text-zinc-500 hover:text-zinc-300 transition">✕ Close</button>
            </div>
            {total === 0 ? (
              <div className="p-4 rounded border border-brand-green/30 bg-brand-green/5 text-brand-green text-sm text-center">
                ✅ No issues found — the codebase looks good!
              </div>
            ) : (
              <div className="space-y-5">
                <Section label="Security" icon="🔒" findings={analyzeResult.security} prefix="sec" />
                <Section label="Performance" icon="⚡" findings={analyzeResult.performance} prefix="perf" />
                <Section label="Best Practices" icon="📋" findings={analyzeResult.best_practices} prefix="bp" />
              </div>
            )}
          </div>
        );
      })()}

      <div className="flex gap-1 border-b border-zinc-800">
        <button
          onClick={() => setTab("files")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px ${tab === "files" ? "border-brand-green text-brand-green" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
        >
          Files
        </button>
        <button
          onClick={() => setTab("pipelines")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px ${tab === "pipelines" ? "border-brand-green text-brand-green" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
        >
          Pipelines
        </button>
        <button
          onClick={() => setTab("vulnerabilities")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px flex items-center gap-2 ${tab === "vulnerabilities" ? "border-brand-green text-brand-green" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
        >
          Vulnerabilities
          {vulnDetail && (vulnDetail.critical + vulnDetail.high + vulnDetail.image_critical + vulnDetail.image_high > 0) && (
            <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
              {vulnDetail.critical + vulnDetail.high + vulnDetail.image_critical + vulnDetail.image_high}
            </span>
          )}
        </button>
        <button
          onClick={() => { setTab("commits"); if (commits.length === 0) loadCommits(); }}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px ${tab === "commits" ? "border-brand-green text-brand-green" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
        >
          Commits
        </button>
      </div>

      {tab === "files" && (
        <div className="glass-card p-4">
          {userHasKeys === false && (
            <div className="mb-4 p-3 rounded border border-yellow-500/40 bg-yellow-500/10 text-yellow-300 text-sm flex items-center gap-3">
              <span>⚠️</span>
              <span>
                No workspace with Bitbucket credentials is assigned to your group. Contact your administrator.
              </span>
            </div>
          )}

          {stagedFiles.length > 0 && (
            <div className="mb-4 p-4 rounded border border-brand-gold/30 bg-brand-gold/5">
              <h3 className="text-sm font-semibold text-brand-gold mb-3">Staged files ({stagedFiles.length})</h3>
              <div className="space-y-1 mb-3">
                {stagedFiles.map(f => (
                  <div key={f.path} className="flex items-center justify-between px-3 py-1.5 bg-zinc-900 rounded text-xs">
                    <span className="text-zinc-300 font-mono">{f.path}</span>
                    <button onClick={() => removeStagedFile(f.path)} className="text-zinc-500 hover:text-red-400 transition ml-3">✕</button>
                  </div>
                ))}
              </div>
              <div className="flex gap-3 flex-wrap">
                <input
                  type="text"
                  value={stagedCommitMessage}
                  onChange={e => setStagedCommitMessage(e.target.value)}
                  placeholder="Commit message"
                  className="input-tech flex-1 text-sm min-w-0"
                />
                <input
                  type="text"
                  value={stagedCommitBranch}
                  onChange={e => setStagedCommitBranch(e.target.value)}
                  placeholder="Branch"
                  className="input-tech w-32 text-sm"
                />
                <button onClick={handleCommitStaged} disabled={stagedCommitting} className="btn-primary px-4 py-2 text-sm disabled:opacity-50 whitespace-nowrap">
                  {stagedCommitting ? "Committing..." : `Commit ${stagedFiles.length} file(s)`}
                </button>
              </div>
              {stagedError && <p className="text-red-400 text-sm mt-2">{stagedError}</p>}
              {stagedSuccess && <p className="text-brand-green text-sm mt-2">{stagedSuccess}</p>}
            </div>
          )}

          <div className="flex items-center gap-3 mb-4 flex-wrap">
            {branches.length > 0 && (
              <select
                value={selectedBranch}
                onChange={e => {
                  const b = e.target.value;
                  setSelectedBranch(b);
                  setPathHistory([]);
                  setCurrentPath("");
                  loadSrc("", b);
                }}
                className="input-tech text-xs py-1 px-2 w-auto"
              >
                <option value="">main (default)</option>
                {branches.filter(b => b !== "main").map(b => (
                  <option key={b} value={b}>{b}</option>
                ))}
              </select>
            )}
            <div className="flex items-center gap-2 text-sm flex-1">
            <button onClick={() => { setPathHistory([]); setCurrentPath(""); loadSrc(""); }} className="text-brand-green hover:underline">
              {repoName}
            </button>
            {currentPath.split("/").filter(Boolean).map((part, i, arr) => {
              const path = arr.slice(0, i + 1).join("/");
              return (
                <span key={path} className="flex items-center gap-2">
                  <span className="text-zinc-600">/</span>
                  <button onClick={() => { setPathHistory(h => h.slice(0, i)); setCurrentPath(path); loadSrc(path); }} className="text-brand-green hover:underline">
                    {part}
                  </button>
                </span>
              );
            })}
            </div>
          </div>

          {filesLoading && <div className="text-center py-8 text-zinc-500">Loading...</div>}

          {!filesLoading && dirEntries !== null && (
            <div className="space-y-1">
              {pathHistory.length > 0 && (
                <button onClick={navigateBack} className="w-full text-left px-3 py-2 rounded hover:bg-zinc-800 text-sm text-zinc-400 transition flex items-center gap-2">
                  <span>📁</span> ..
                </button>
              )}
              {dirEntries.length === 0 && <p className="text-zinc-500 text-sm py-4 text-center italic">Empty directory.</p>}
              {dirEntries.map(entry => (
                <button
                  key={entry.path}
                  onClick={() => {
                    if (entry.type === "commit_directory") {
                      navigateTo(entry.path);
                    } else {
                      setPathHistory(h => [...h, currentPath]);
                      setCurrentPath(entry.path);
                      loadSrc(entry.path);
                    }
                  }}
                  className="w-full text-left px-3 py-2 rounded hover:bg-zinc-800 text-sm transition flex items-center gap-3"
                >
                  <span>{entry.type === "commit_directory" ? "📁" : "📄"}</span>
                  <span className={entry.type === "commit_directory" ? "text-brand-gold" : "text-zinc-200"}>
                    {entry.path.split("/").pop()}
                  </span>
                  {entry.size !== undefined && entry.type === "commit_file" && (
                    <span className="ml-auto text-zinc-600 text-xs">{(entry.size / 1024).toFixed(1)} KB</span>
                  )}
                </button>
              ))}
            </div>
          )}

          {!filesLoading && fileContent !== null && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <button onClick={navigateBack} className="text-sm text-zinc-400 hover:text-zinc-200 transition flex items-center gap-1">
                  ← Back
                </button>
                {!editing && (
                  <button
                    onClick={startEditing}
                    disabled={userHasKeys === false}
                    title={userHasKeys === false ? "Register your SSH keys in Profile to enable editing" : undefined}
                    className="btn-primary px-3 py-1 text-xs disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    Edit file
                  </button>
                )}
              </div>

              {commitSuccess && (
                <div className="mb-3 p-2 rounded bg-brand-green/10 border border-brand-green/30 text-brand-green text-sm">
                  {commitSuccess}
                </div>
              )}

              {!editing ? (
                <>
                  <div className="bg-zinc-950 border border-zinc-800 rounded text-xs font-mono overflow-auto max-h-[70vh]">
                    {fileContent.split("\n").map((ln, idx) => {
                      const lineNum = idx + 1;
                      const isHighlighted = highlightLine === lineNum;
                      return (
                        <div
                          key={idx}
                          id={`L${lineNum}`}
                          className={`flex min-w-0 ${isHighlighted ? "bg-yellow-500/20 ring-1 ring-inset ring-yellow-500/40" : "hover:bg-zinc-900"}`}
                        >
                          <span className="select-none text-zinc-600 text-right w-12 shrink-0 px-2 py-0.5 border-r border-zinc-800">
                            {lineNum}
                          </span>
                          <span className={`px-3 py-0.5 whitespace-pre flex-1 min-w-0 ${isHighlighted ? "text-yellow-200" : "text-brand-green"}`}>
                            {ln}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                  {highlightLine && (
                    <p className="text-xs text-yellow-400/70 mt-1">Line {highlightLine} highlighted from Code Analyze finding</p>
                  )}
                </>
              ) : (
                <div className="space-y-3">
                  <textarea
                    value={editContent}
                    onChange={(e) => setEditContent(e.target.value)}
                    className="w-full bg-zinc-950 border border-zinc-700 rounded p-4 text-xs text-brand-green font-mono resize-y min-h-[400px] focus:outline-none focus:border-brand-green"
                    spellCheck={false}
                  />
                  <div className="flex gap-3">
                    <input
                      type="text"
                      value={commitMessage}
                      onChange={(e) => setCommitMessage(e.target.value)}
                      placeholder="Commit message"
                      className="input-tech flex-1 text-sm"
                    />
                    <input
                      type="text"
                      value={commitBranch}
                      onChange={(e) => setCommitBranch(e.target.value)}
                      placeholder="Branch"
                      className="input-tech w-32 text-sm"
                    />
                  </div>
                  {commitError && (
                    <p className="text-red-400 text-sm">{commitError}</p>
                  )}
                  <div className="flex gap-2 justify-end flex-wrap">
                    <button onClick={() => setEditing(false)} className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition">
                      Cancel
                    </button>
                    <button onClick={stageFile} className="px-4 py-2 text-sm border border-brand-gold/50 text-brand-gold hover:bg-brand-gold/10 rounded transition">
                      + Stage file
                    </button>
                    <button onClick={handleCommit} disabled={committing} className="btn-primary px-4 py-2 text-sm disabled:opacity-50">
                      {committing ? "Committing..." : "Commit changes"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {tab === "pipelines" && (
        <div className="space-y-3">
          <div className="glass-card p-4 flex items-center gap-3 flex-wrap">
            <span className="text-sm text-zinc-400 font-medium">Run pipeline:</span>
            <select
              className="input-tech text-sm py-1.5 px-3 w-40"
              value={triggerBranch}
              onChange={e => setTriggerBranch(e.target.value)}
            >
              {branches.map(b => <option key={b} value={b}>{b}</option>)}
              {!branches.includes(triggerBranch) && <option value={triggerBranch}>{triggerBranch}</option>}
            </select>
            <button
              onClick={triggerPipeline}
              disabled={triggering}
              className="btn-primary text-sm px-4 py-1.5"
            >
              {triggering ? "Starting..." : "▶ Run"}
            </button>
          </div>

          {pipelinesLoading && <div className="text-center py-8 text-zinc-500">Loading pipelines...</div>}
          {!pipelinesLoading && pipelines.length === 0 && (
            <div className="glass-card p-8 text-center text-zinc-500">
              No pipelines found. The repository may not have been pushed yet.
            </div>
          )}
          {pipelines.map(pipeline => {
            const status = pipelineStatus(pipeline);
            return (
              <div key={pipeline.uuid} className="glass-card overflow-hidden">
                <button
                  onClick={() => togglePipeline(pipeline.uuid)}
                  className="w-full flex items-center gap-4 px-4 py-3 hover:bg-zinc-800/50 transition text-left"
                >
                  <span className={`text-xs px-2 py-0.5 rounded border font-mono ${statusColor(status)}`}>
                    {status}
                  </span>
                  <span className="text-sm font-medium text-zinc-200">
                    Build #{pipeline.build_number}
                  </span>
                  <span className="text-xs text-zinc-500 ml-auto">
                    {new Date(pipeline.created_on).toLocaleString("en-US")}
                  </span>
                  {pipeline.target?.ref_name && (
                    <span className="text-xs text-zinc-500 bg-zinc-800 px-2 py-0.5 rounded">
                      {pipeline.target.ref_name}
                    </span>
                  )}
                  {isRunning(pipeline) && (
                    <button
                      onClick={e => { e.stopPropagation(); stopPipeline(pipeline.uuid); }}
                      disabled={stoppingPipeline === pipeline.uuid}
                      className="text-xs px-2 py-0.5 rounded border border-red-500/50 text-red-400 bg-red-500/10 hover:bg-red-500/20 transition"
                    >
                      {stoppingPipeline === pipeline.uuid ? "Stopping..." : "■ Stop"}
                    </button>
                  )}
                  <span className="text-zinc-500 text-xs">{expandedPipeline === pipeline.uuid ? "▲" : "▼"}</span>
                </button>

                {expandedPipeline === pipeline.uuid && (
                  <div className="border-t border-zinc-800 px-4 pb-4 pt-2 space-y-2">
                    {!steps[pipeline.uuid] && <p className="text-zinc-500 text-sm">Loading steps...</p>}
                    {(steps[pipeline.uuid] || []).map(step => {
                      const stepKey = `${pipeline.uuid}/${step.uuid}`;
                      const stepStatus = step.state.result?.name || step.state.name;
                      return (
                        <div key={step.uuid} className="rounded border border-zinc-800">
                          <button
                            onClick={() => toggleStepLog(pipeline.uuid, step.uuid)}
                            className="w-full flex items-center gap-3 px-3 py-2 hover:bg-zinc-800/50 transition text-left text-sm"
                          >
                            <span className={`text-xs px-1.5 py-0.5 rounded border ${statusColor(stepStatus)}`}>{stepStatus}</span>
                            <span className="text-zinc-300">{step.name}</span>
                            <span className="ml-auto text-xs text-zinc-500">{expandedStep === stepKey ? "Hide log ▲" : "View log ▼"}</span>
                          </button>
                          {expandedStep === stepKey && (
                            <div className="border-t border-zinc-800 p-2">
                              {!stepLogs[stepKey] ? (
                                <p className="text-zinc-500 text-xs p-2">Loading log...</p>
                              ) : (
                                <pre className="text-xs font-mono text-zinc-300 bg-zinc-950 p-3 rounded overflow-auto max-h-96 whitespace-pre-wrap">
                                  {stepLogs[stepKey] || "(empty log)"}
                                </pre>
                              )}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {tab === "vulnerabilities" && (
        <div className="space-y-4">
          {vulnLoading && <div className="text-center py-8 text-zinc-500">Loading vulnerabilities...</div>}

          {!vulnLoading && !vulnDetail && (
            <div className="glass-card p-10 text-center text-zinc-500">
              No scan results yet. Click <strong>Security Scan</strong> to run the first scan.
            </div>
          )}

          {vulnDetail && (() => {
            const sevColor = (s: string) => {
              switch (s?.toUpperCase()) {
                case "CRITICAL": return "text-red-500 font-bold";
                case "HIGH":     return "text-orange-500 font-bold";
                case "MEDIUM":   return "text-yellow-500";
                case "LOW":      return "text-green-500";
                default:         return "text-zinc-400";
              }
            };

            const activeFindings = vulnTab === "code" ? (vulnDetail.findings || []) : (vulnDetail.image_findings || []);
            const filtered = activeFindings.filter(f => {
              const matchSev = vulnSevFilter === "ALL" || f.severity?.toUpperCase() === vulnSevFilter;
              const matchSearch = !vulnSearch ||
                f.title?.toLowerCase().includes(vulnSearch.toLowerCase()) ||
                f.vuln_id?.toLowerCase().includes(vulnSearch.toLowerCase()) ||
                f.pkg?.toLowerCase().includes(vulnSearch.toLowerCase()) ||
                f.target?.toLowerCase().includes(vulnSearch.toLowerCase());
              return matchSev && matchSearch;
            });

            return (
              <>
                <div className="flex gap-1 border-b border-zinc-800 mb-2">
                  <button
                    onClick={() => { setVulnTab("code"); setVulnSevFilter("ALL"); setVulnSearch(""); }}
                    className={`px-4 py-2 text-xs font-medium border-b-2 transition -mb-px flex items-center gap-2 ${vulnTab === "code" ? "border-brand-green text-brand-green" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
                  >
                    Code Scan
                    <span className="flex gap-1">
                      <span className="px-1.5 py-0.5 rounded bg-red-900/40 text-red-400 border border-red-500/30 text-[10px]">C:{vulnDetail.critical}</span>
                      <span className="px-1.5 py-0.5 rounded bg-orange-900/40 text-orange-400 border border-orange-500/30 text-[10px]">H:{vulnDetail.high}</span>
                    </span>
                  </button>
                  <button
                    onClick={() => { setVulnTab("image"); setVulnSevFilter("ALL"); setVulnSearch(""); }}
                    className={`px-4 py-2 text-xs font-medium border-b-2 transition -mb-px flex items-center gap-2 ${vulnTab === "image" ? "border-brand-green text-brand-green" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
                  >
                    Image Scan
                    {vulnDetail.scanned_image && !vulnDetail.image_error ? (
                      <span className="flex gap-1">
                        <span className="px-1.5 py-0.5 rounded bg-red-900/40 text-red-400 border border-red-500/30 text-[10px]">C:{vulnDetail.image_critical}</span>
                        <span className="px-1.5 py-0.5 rounded bg-orange-900/40 text-orange-400 border border-orange-500/30 text-[10px]">H:{vulnDetail.image_high}</span>
                      </span>
                    ) : (
                      <span className="text-[10px] text-zinc-500 italic">{vulnDetail.image_error ? "error" : "not scanned"}</span>
                    )}
                  </button>
                </div>

                <div className="flex gap-3 flex-wrap items-center justify-between">
                  <div className="flex gap-2 text-xs font-semibold items-center">
                    {vulnTab === "code" ? (
                      <>
                        <span className="px-2 py-1 rounded border bg-red-900/40 text-red-400 border-red-500/40">C: {vulnDetail.critical}</span>
                        <span className="px-2 py-1 rounded border bg-orange-900/40 text-orange-400 border-orange-500/40">H: {vulnDetail.high}</span>
                        <span className="px-2 py-1 rounded border bg-yellow-900/40 text-yellow-400 border-yellow-500/40">M: {vulnDetail.medium}</span>
                        <span className="px-2 py-1 rounded border bg-green-900/40 text-green-400 border-green-500/40">L: {vulnDetail.low}</span>
                      </>
                    ) : (
                      <>
                        <span className="px-2 py-1 rounded border bg-red-900/40 text-red-400 border-red-500/40">C: {vulnDetail.image_critical}</span>
                        <span className="px-2 py-1 rounded border bg-orange-900/40 text-orange-400 border-orange-500/40">H: {vulnDetail.image_high}</span>
                        <span className="px-2 py-1 rounded border bg-yellow-900/40 text-yellow-400 border-yellow-500/40">M: {vulnDetail.image_medium}</span>
                        <span className="px-2 py-1 rounded border bg-green-900/40 text-green-400 border-green-500/40">L: {vulnDetail.image_low}</span>
                        {vulnDetail.scanned_image && <span className="text-zinc-500 font-mono text-[10px] ml-1">{vulnDetail.scanned_image}</span>}
                        {vulnDetail.image_error && <span className="text-red-400 text-xs ml-1">{vulnDetail.image_error}</span>}
                      </>
                    )}
                    <span className="text-zinc-500 font-normal ml-2">Last scan: {new Date(vulnDetail.scanned_at).toLocaleString("en-US")}</span>
                  </div>
                  <div className="flex gap-2 items-center flex-wrap">
                    <div className="flex gap-1">
                      {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
                        <button key={s} onClick={() => setVulnSevFilter(s)}
                          className={`px-2.5 py-1 rounded text-xs font-medium border transition ${vulnSevFilter === s ? "border-brand-green text-brand-green bg-brand-green/10" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}>
                          {s}
                        </button>
                      ))}
                    </div>
                    <input type="text" placeholder="Search CVE, package, file..." value={vulnSearch}
                      onChange={e => setVulnSearch(e.target.value)} className="input-tech text-sm py-1 w-56" />
                  </div>
                </div>

                {vulnTab === "image" && vulnDetail.image_error && (
                  <div className="p-3 rounded border border-yellow-500/30 bg-yellow-500/10 text-yellow-400 text-xs">{vulnDetail.image_error}</div>
                )}

                {filtered.length === 0 ? (
                  <p className="text-zinc-500 text-sm italic py-4">No findings match the current filter.</p>
                ) : (
                  <div className="glass-card overflow-x-auto">
                    <table className="w-full text-sm border-collapse">
                      <thead>
                        <tr className="border-b border-zinc-700">
                          <th className="text-left py-2 px-3 text-zinc-400 font-medium">Severity</th>
                          <th className="text-left py-2 px-3 text-zinc-400 font-medium">ID / CVE</th>
                          <th className="text-left py-2 px-3 text-zinc-400 font-medium">Title</th>
                          <th className="text-left py-2 px-3 text-zinc-400 font-medium">File / Target</th>
                          <th className="text-left py-2 px-3 text-zinc-400 font-medium">Package</th>
                          <th className="text-left py-2 px-3 text-zinc-400 font-medium">Fixed in</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filtered.map((f, i) => (
                          <tr key={i} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                            <td className={`py-2 px-3 font-mono text-xs ${sevColor(f.severity)}`}>{f.severity}</td>
                            <td className="py-2 px-3 font-mono text-xs">
                              {f.type === "vulnerability" && f.vuln_id ? (
                                <a href={`https://nvd.nist.gov/vuln/detail/${f.vuln_id}`} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline">{f.vuln_id}</a>
                              ) : (
                                <span className="text-zinc-300">{f.vuln_id}</span>
                              )}
                            </td>
                            <td className="py-2 px-3 text-zinc-300 max-w-xs truncate" title={f.title}>{f.title}</td>
                            <td className="py-2 px-3 font-mono text-xs text-zinc-500 max-w-[160px] truncate" title={f.target}>{f.target}</td>
                            <td className="py-2 px-3 font-mono text-xs text-zinc-400">{f.pkg || "—"}</td>
                            <td className="py-2 px-3 font-mono text-xs text-brand-green">{f.fixed || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            );
          })()}
        </div>
      )}

      {tab === "commits" && (
        <div className="glass-card p-4 space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            {branches.length > 0 && (
              <select
                value={commitsBranch}
                onChange={e => {
                  setCommitsBranch(e.target.value);
                  loadCommits(e.target.value);
                }}
                className="input-tech text-xs py-1 px-2 w-auto"
              >
                <option value="main">main</option>
                {branches.filter(b => b !== "main").map(b => (
                  <option key={b} value={b}>{b}</option>
                ))}
              </select>
            )}
            <button
              onClick={() => loadCommits()}
              disabled={commitsLoading}
              className="text-xs text-brand-green hover:text-brand-gold disabled:opacity-40 transition-colors"
            >
              ↻ Refresh
            </button>
          </div>

          {commitsLoading ? (
            <div className="text-sm text-zinc-400 py-6 text-center">Loading commits...</div>
          ) : commits.length === 0 ? (
            <div className="text-sm text-zinc-400 py-6 text-center">No commits found.</div>
          ) : (
            <div className="divide-y divide-zinc-800">
              {commits.map(c => (
                <div key={c.hash} className="py-3 flex items-start gap-3">
                  <span className="font-mono text-xs text-brand-green bg-brand-green/10 border border-brand-green/30 rounded px-2 py-0.5 shrink-0 mt-0.5">
                    {c.short_hash}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-zinc-100 truncate">{c.message}</p>
                    <p className="text-xs text-zinc-500 mt-0.5">
                      <span className="text-zinc-400">{c.author}</span>
                      {" · "}
                      {c.date ? new Date(c.date).toLocaleString() : ""}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
