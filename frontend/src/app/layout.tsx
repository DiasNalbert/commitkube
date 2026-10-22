import type { Metadata } from "next";
import { headers } from "next/headers";
import { Onest, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import Shell from "./components/shell/Shell";
import SessionGate from "./components/SessionGate";
import ThemeProvider from "./components/ThemeProvider";

// Downloaded at build time and served from this origin, so the page's CSP
// needs no exception for a font host.
const onest = Onest({ subsets: ["latin"], weight: ["300", "400", "500", "600", "700"], variable: "--font-onest", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], weight: ["300", "400", "500"], variable: "--font-jetbrains", display: "swap" });

export const metadata: Metadata = {
  title: "CommitKube",
  description: "Kubernetes, delivery and security in one place",
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
    <html lang="en" className={`dark ${onest.variable} ${mono.variable}`} suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: `(function(){try{var t=localStorage.getItem('theme');if(t==='light'){document.documentElement.classList.remove('dark');}else{document.documentElement.classList.add('dark');}}catch(e){}})();` }} />
      </head>
      <body className="antialiased min-h-screen">
        <ThemeProvider />
        <SessionGate>
          <Shell>{children}</Shell>
        </SessionGate>
      </body>
    </html>
  );
}
