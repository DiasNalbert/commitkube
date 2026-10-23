import type { Metadata } from "next";
import { headers } from "next/headers";
import localFont from "next/font/local";
import "./globals.css";
import Shell from "./components/shell/Shell";
import SessionGate from "./components/SessionGate";
import ThemeProvider from "./components/ThemeProvider";

// The fonts come from npm packages (OFL-licensed) and are served from this
// origin: the page's CSP needs no font host, and the build needs no network
// beyond the npm registry it already uses. next/font/google fetched them
// from Google at build time, which fails wherever the build cannot reach it.
const onest = localFont({
  src: "../../node_modules/@fontsource-variable/onest/files/onest-latin-wght-normal.woff2",
  weight: "100 900", variable: "--font-onest", display: "swap",
});
const mono = localFont({
  src: "../../node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2",
  weight: "100 800", variable: "--font-jetbrains", display: "swap",
});

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
