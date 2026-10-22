import type { Metadata } from "next";
import { headers } from "next/headers";
import "./globals.css";
import Sidebar from "./components/Sidebar";
import AppShell from "./components/AppShell";
import ThemeProvider from "./components/ThemeProvider";
import SessionGate from "./components/SessionGate";

export const metadata: Metadata = {
  title: "CommitKube | DevOps Automation",
  description: "Automated K8s deployment platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // The page's CSP only runs scripts carrying this request's nonce, the
  // theme script below included. See src/middleware.ts.
  const nonce = headers().get("x-nonce") ?? undefined;
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: `(function(){try{var t=localStorage.getItem('theme');if(t==='light'){document.documentElement.classList.remove('dark');}else{document.documentElement.classList.add('dark');}}catch(e){}})();` }} />
      </head>
      <body className="antialiased min-h-screen font-sans flex">
        <ThemeProvider />
        <SessionGate>
        <Sidebar />
        <AppShell>
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full flex-1">
            {children}
          </main>
          <footer className="py-5 text-center text-xs bg-brand-green/10 border-t border-brand-green/30">
            <span className="text-zinc-400">CommitKube &copy; {new Date().getFullYear()}</span>
          </footer>
        </AppShell>
        </SessionGate>
      </body>
    </html>
  );
}
