import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "./components/Sidebar";
import AppShell from "./components/AppShell";
import ThemeProvider from "./components/ThemeProvider";

export const metadata: Metadata = {
  title: "CommitKube | DevOps Automation",
  description: "Automated K8s deployment platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: `(function(){try{var t=localStorage.getItem('theme');if(t==='light'){document.documentElement.classList.remove('dark');}else{document.documentElement.classList.add('dark');}}catch(e){}})();` }} />
      </head>
      <body className="antialiased min-h-screen font-sans flex">
        <ThemeProvider />
        <Sidebar />
        <AppShell>
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full flex-1">
            {children}
          </main>
          <footer className="py-5 text-center text-xs bg-brand-green/10 border-t border-brand-green/30">
            <span className="text-zinc-400">CommitKube &copy; {new Date().getFullYear()} &mdash; Development environment provided by{" "}
              <a href="https://gobsolucoes.com.br/" target="_blank" rel="noopener noreferrer" className="text-brand-green font-semibold hover:text-brand-gold transition-colors underline underline-offset-2">
                Gob Soluções
              </a>
            </span>
          </footer>
        </AppShell>
      </body>
    </html>
  );
}
