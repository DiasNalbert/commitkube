"use client";

import { useState, useEffect } from "react";

export default function ThemeToggle() {
  const [dark, setDark] = useState(true);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("theme");
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const isDark = saved ? saved === "dark" : prefersDark;
    setDark(isDark);
    setMounted(true);
  }, []);

  const toggle = () => {
    const next = !dark;
    setDark(next);
    localStorage.setItem("theme", next ? "dark" : "light");
    document.documentElement.classList.toggle("dark", next);
  };

  if (!mounted) return <div className="w-8 h-8" />;

  return (
    <button
      onClick={toggle}
      title={dark ? "Mudar para modo claro" : "Mudar para modo escuro"}
      className="w-8 h-8 flex items-center justify-center rounded-full border border-brand-green/30 hover:bg-brand-green/10 hover:scale-110 active:scale-95 transition-all duration-150 text-base"
    >
      {dark ? "☀️" : "🌙"}
    </button>
  );
}
