"use client";
import { clearPermissions } from "@/lib/permissions";

export default function LogoutButton() {
  const handleLogout = () => {
    // The permission answer is cached for the session; leaving it would let
    // the next person to sign in on this browser start with the last one's nav.
    clearPermissions();
    localStorage.removeItem("token");
    localStorage.removeItem("refresh_token");
    window.location.href = "/login";
  };

  return (
    <button
      onClick={handleLogout}
      className="ml-4 text-xs font-semibold text-brand-green border border-brand-green/30 px-3 py-1.5 rounded-full hover:bg-brand-green/10 transition"
    >
      Logout
    </button>
  );
}
