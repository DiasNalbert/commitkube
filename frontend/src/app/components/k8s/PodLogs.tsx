"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";

interface LogLine {
  timestamp: string;
  content: string;
}

const TAIL_OPTIONS = [100, 500, 1000, 5000];

/**
 * Live log viewer for one pod, reading from the kubelet through the API server.
 *
 * Uses fetch with a stream reader rather than EventSource: EventSource cannot
 * send an Authorization header, which would force the JWT into the query string
 * where it lands in nginx access logs.
 */
export default function PodLogs({
  namespace,
  pod,
  containers,
}: {
  namespace: string;
  pod: string;
  containers: string[];
}) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [container, setContainer] = useState(containers[0] ?? "");
  const [tail, setTail] = useState(500);
  const [previous, setPrevious] = useState(false);
  const [following, setFollowing] = useState(true);
  const [error, setError] = useState("");
  const [connecting, setConnecting] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const pinnedRef = useRef(true);

  const stop = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  const start = useCallback(async () => {
    stop();
    setLines([]);
    setError("");
    setConnecting(true);

    const controller = new AbortController();
    abortRef.current = controller;

    const params = new URLSearchParams({ namespace, pod, tail: String(tail) });
    if (container) params.set("container", container);

    // Reading the previous container is a one-shot read: the dead container
    // writes nothing more, so there is no stream to follow.
    const path = previous
      ? `/kubernetes/pods/logs?${params.toString()}&previous=true`
      : `/kubernetes/pods/logs/stream?${params.toString()}`;

    try {
      const res = await apiFetch(path, { signal: controller.signal });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.error ?? `Request failed (${res.status})`);
        setConnecting(false);
        return;
      }

      if (previous) {
        const body = await res.json();
        const text: string = body.logs ?? "";
        setLines(
          text.split("\n").filter(Boolean).map(l => {
            const i = l.indexOf(" ");
            return i > 0 && !Number.isNaN(Date.parse(l.slice(0, i)))
              ? { timestamp: l.slice(0, i), content: l.slice(i + 1) }
              : { timestamp: "", content: l };
          })
        );
        setConnecting(false);
        return;
      }

      setConnecting(false);
      const reader = res.body?.getReader();
      if (!reader) {
        setError("This browser cannot read the log stream");
        return;
      }

      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // SSE frames are separated by a blank line; keep any partial tail.
        const frames = buffer.split("\n\n");
        buffer = frames.pop() ?? "";

        const batch: LogLine[] = [];
        for (const frame of frames) {
          for (const raw of frame.split("\n")) {
            if (!raw.startsWith("data: ")) continue;
            try {
              const parsed = JSON.parse(raw.slice(6));
              if (parsed.content !== undefined) batch.push(parsed as LogLine);
            } catch {
              // a partial frame; the next read completes it
            }
          }
        }
        if (batch.length) {
          // Cap retained lines so a chatty pod cannot grow the tab's memory
          // without bound.
          setLines(prev => [...prev, ...batch].slice(-10_000));
        }
      }
    } catch (e) {
      if ((e as Error).name !== "AbortError") {
        setError(e instanceof Error ? e.message : "Log stream failed");
      }
      setConnecting(false);
    }
  }, [namespace, pod, container, tail, previous, stop]);

  useEffect(() => {
    start();
    return stop;
  }, [start, stop]);

  // Follow the tail only while the reader is already at the bottom, so reading
  // back through history is not yanked away by new lines.
  useEffect(() => {
    const el = scrollRef.current;
    if (el && following && pinnedRef.current) {
      el.scrollTop = el.scrollHeight;
    }
  }, [lines, following]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    pinnedRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {containers.length > 1 && (
          <select
            value={container}
            onChange={e => setContainer(e.target.value)}
            className="px-2 py-1.5 text-xs rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]"
          >
            {containers.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        )}

        <select
          value={tail}
          onChange={e => setTail(Number(e.target.value))}
          className="px-2 py-1.5 text-xs rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]"
        >
          {TAIL_OPTIONS.map(n => <option key={n} value={n}>last {n} lines</option>)}
        </select>

        <label className="flex items-center gap-1.5 text-xs text-zinc-500 dark:text-zinc-400">
          <input
            type="checkbox"
            checked={previous}
            onChange={e => setPrevious(e.target.checked)}
            className="accent-brand-green"
          />
          Previous container
        </label>

        {!previous && (
          <label className="flex items-center gap-1.5 text-xs text-zinc-500 dark:text-zinc-400">
            <input
              type="checkbox"
              checked={following}
              onChange={e => setFollowing(e.target.checked)}
              className="accent-brand-green"
            />
            Auto-scroll
          </label>
        )}

        <span className="text-xs text-zinc-500 dark:text-zinc-400 ml-auto">
          {connecting ? "connecting…" : previous ? `${lines.length} lines` : (
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-brand-green animate-pulse" />
              live · {lines.length} lines
            </span>
          )}
        </span>

        <button
          onClick={start}
          className="px-2.5 py-1.5 text-xs rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition"
        >
          Reconnect
        </button>
      </div>

      {previous && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          Showing the log of the container instance that already exited — this is where the
          reason for a CrashLoopBackOff usually is.
        </p>
      )}

      {error ? (
        <div className="glass-card p-4 border-red-500/30">
          <p className="text-sm text-red-500 dark:text-red-400 font-medium">Cannot read logs</p>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 break-words">{error}</p>
        </div>
      ) : (
        <div
          ref={scrollRef}
          onScroll={onScroll}
          className="h-[420px] overflow-auto rounded-lg bg-zinc-100 dark:bg-zinc-950 border border-[var(--card-border)] p-3 font-mono text-xs leading-relaxed"
        >
          {lines.length === 0 ? (
            <p className="text-zinc-500">{connecting ? "Connecting…" : "No output yet."}</p>
          ) : (
            lines.map((l, i) => (
              <div key={i} className="flex gap-3 whitespace-pre-wrap break-all">
                {l.timestamp && (
                  <span className="text-zinc-400 dark:text-zinc-600 shrink-0 select-none">
                    {new Date(l.timestamp).toLocaleTimeString([], { hour12: false })}
                  </span>
                )}
                <span className="text-zinc-800 dark:text-zinc-300">{l.content}</span>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
