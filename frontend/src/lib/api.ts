const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080/api";

async function refreshAccessToken(): Promise<string | null> {
  const refreshToken = localStorage.getItem("refresh_token");
  if (!refreshToken) return null;

  const res = await fetch(`${API}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!res.ok) {
    localStorage.removeItem("token");
    localStorage.removeItem("refresh_token");
    window.location.href = "/login";
    return null;
  }

  const data = await res.json();
  localStorage.setItem("token", data.token);
  return data.token;
}

export async function apiFetch(
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  const token = localStorage.getItem("token");

  const makeHeaders = (t: string | null) => ({
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
    ...(t ? { Authorization: `Bearer ${t}` } : {}),
  });

  let res = await fetch(`${API}${path}`, {
    ...options,
    headers: makeHeaders(token),
  });

  if (res.status === 401) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      res = await fetch(`${API}${path}`, {
        ...options,
        headers: makeHeaders(newToken),
      });
    }
  }

  return res;
}

export { API };
