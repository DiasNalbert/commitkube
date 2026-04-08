"use client";

export default function LogoutButton() {
  const handleLogout = () => {
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
