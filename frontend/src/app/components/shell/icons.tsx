import type { ModuleKey } from "./nav";

/** The mark: two filled squares and two outlined, green and gold. */
export function LogoMark({ className = "w-[22px] h-[22px]" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" className={`${className} shrink-0`} aria-hidden>
      <rect x="1" y="1" width="10" height="10" fill="#10b981" />
      <rect x="13" y="1" width="10" height="10" fill="none" stroke="#10b981" strokeWidth="1.5" />
      <rect x="1" y="13" width="10" height="10" fill="none" stroke="#10b981" strokeWidth="1.5" />
      <rect x="13" y="13" width="10" height="10" fill="#fbbf24" />
    </svg>
  );
}

/** One full-colour icon per module, so the rail reads at a glance even
 *  collapsed to its 60px column. */
export function ModuleIcon({ module }: { module: ModuleKey }) {
  switch (module) {
    case "cluster":
      return (
        <svg viewBox="0 0 24 24" className="w-5 h-5 shrink-0" aria-hidden>
          <path d="M12 1.2l8.6 4.15 2.12 9.3-5.95 7.46H7.23L1.28 14.65 3.4 5.35z" fill="#326ce5" stroke="#326ce5" strokeWidth="1.2" strokeLinejoin="round" />
          <g fill="none" stroke="#ffffff" strokeWidth="1.5" strokeLinecap="round">
            <circle cx="12" cy="12" r="3.6" />
            <path d="M12 8.4V4.6M14.8 9.8l2.95-2.35M15.5 12.8l3.7.85M13.55 15.25l1.65 3.4M10.45 15.25l-1.65 3.4M8.5 12.8l-3.7.85M9.2 9.8L6.25 7.45" />
          </g>
          <circle cx="12" cy="12" r="1.1" fill="#ffffff" />
        </svg>
      );
    case "delivery":
      return (
        <svg viewBox="0 0 24 24" className="w-[19px] h-[19px] shrink-0" aria-hidden>
          <path d="M23.55 10.93 13.07.45a1.55 1.55 0 0 0-2.19 0L8.7 2.63l2.76 2.76a1.84 1.84 0 0 1 2.33 2.35l2.66 2.66a1.84 1.84 0 1 1-1.1 1.04l-2.48-2.48v6.53a1.84 1.84 0 1 1-1.52-.05V8.85a1.84 1.84 0 0 1-1-2.42L7.63 3.71.45 10.88a1.55 1.55 0 0 0 0 2.2l10.48 10.47a1.55 1.55 0 0 0 2.19 0l10.43-10.43a1.55 1.55 0 0 0 0-2.19z" fill="#f05032" />
        </svg>
      );
    case "security":
      return (
        <svg viewBox="0 0 24 24" className="w-[19px] h-[19px] shrink-0" aria-hidden>
          <path d="M12 1.5 3.5 4.8v6.4c0 5.3 3.6 10 8.5 11.3 4.9-1.3 8.5-6 8.5-11.3V4.8z" fill="#10b981" />
          <path d="M12 1.5v21c4.9-1.3 8.5-6 8.5-11.3V4.8z" fill="#059669" />
          <path d="m8.3 12.1 2.6 2.6 5-5.2" fill="none" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "edge":
      return (
        <svg viewBox="0 0 24 24" className="w-[21px] h-[21px] shrink-0" aria-hidden>
          <path d="M16.2 17.4l.25-.85c.3-1.02.19-1.96-.3-2.65-.45-.63-1.2-1-2.1-1.05l-8.62-.11a.17.17 0 0 1-.14-.07.2.2 0 0 1-.02-.16.24.24 0 0 1 .2-.15l8.7-.11c1.03-.05 2.15-.89 2.54-1.91l.5-1.3a.3.3 0 0 0 .01-.17 5.67 5.67 0 0 0-10.9-.58 2.55 2.55 0 0 0-4 2.67A3.62 3.62 0 0 0 .02 17.2c.01.08.08.15.16.15h15.82c.1 0 .18-.06.2-.15z" fill="#f38020" />
          <path d="M18.93 11.83h-.24c-.05 0-.1.04-.12.09l-.33 1.17c-.3 1.02-.19 1.96.3 2.65.46.63 1.2 1 2.1 1.04l1.84.12c.05 0 .1.03.13.07a.2.2 0 0 1 .02.16.24.24 0 0 1-.21.15l-1.91.12c-1.04.05-2.16.89-2.55 1.91l-.14.36c-.03.07.02.14.1.14h6.58c.08 0 .15-.05.17-.13a4.73 4.73 0 0 0-4.56-5.98z" fill="#faae40" />
        </svg>
      );
    case "vault":
      return (
        <svg viewBox="0 0 24 24" className="w-[19px] h-[19px] shrink-0" aria-hidden>
          <rect x="2" y="2.5" width="20" height="17.5" rx="2.5" fill="#fbbf24" />
          <rect x="4" y="20" width="3" height="2" rx=".6" fill="#b7791f" />
          <rect x="17" y="20" width="3" height="2" rx=".6" fill="#b7791f" />
          <circle cx="11" cy="11.25" r="5" fill="#3a2a05" />
          <circle cx="11" cy="11.25" r="2" fill="#fbbf24" />
          <path d="M11 6.25v2M11 14.25v2M6 11.25h2M14 11.25h2" stroke="#fbbf24" strokeWidth="1.2" />
          <rect x="18.2" y="8" width="1.6" height="6.5" rx=".8" fill="#3a2a05" />
        </svg>
      );
    case "admin":
      return (
        <svg viewBox="0 0 24 24" className="w-[19px] h-[19px] shrink-0" aria-hidden>
          <path fillRule="evenodd" d="M13.9 1.5h-3.8l-.6 2.9a8 8 0 0 0-2 1.2L4.7 4.6 2.8 7.9l2.2 2a8 8 0 0 0 0 2.3l-2.2 2 1.9 3.3 2.8-1a8 8 0 0 0 2 1.2l.6 2.8h3.8l.6-2.8a8 8 0 0 0 2-1.2l2.8 1 1.9-3.3-2.2-2a8 8 0 0 0 0-2.3l2.2-2-1.9-3.3-2.8 1a8 8 0 0 0-2-1.2zM12 15.4a3.4 3.4 0 1 0 0-6.8 3.4 3.4 0 0 0 0 6.8z" fill="#94a3b8" />
          <circle cx="12" cy="12" r="1.6" fill="#64748b" />
        </svg>
      );
  }
}
