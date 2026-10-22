import { NextResponse, type NextRequest } from "next/server";

/** Content-Security-Policy for every page.
 *
 *  The vault runs on the same origin as the rest of the product, so an
 *  injected script anywhere -- a pod name, a commit message, a finding title
 *  rendered somewhere unescaped -- would run with the vault's access: the
 *  sign-in token, and whatever is open in that tab. React escapes what it
 *  renders, which is the first line; this is the second, for the day
 *  something gets past it.
 *
 *  Scripts run only with this request's nonce. Next.js reads the policy from
 *  the request headers and puts the nonce on its own scripts; 'strict-dynamic'
 *  lets the scripts it loads load theirs. Nothing on a page can bring in a
 *  script by writing a <script> tag or an onclick attribute.
 */
function policy(nonce: string): string {
  const dev = process.env.NODE_ENV !== "production";

  // The API is same-origin in the image (/api through nginx). When it is
  // pointed somewhere else, that origin is the one other place the page may
  // talk to.
  const connect = ["'self'"];
  const api = process.env.NEXT_PUBLIC_API_URL;
  if (api && /^https?:\/\//.test(api)) {
    try { connect.push(new URL(api).origin); } catch { /* not a URL; 'self' it is */ }
  }
  if (dev) connect.push("ws:"); // the dev server's hot reload

  return [
    "default-src 'self'",
    // 'wasm-unsafe-eval' is for hash-wasm, the vault's Argon2id. It allows
    // compiling WebAssembly, not eval() of strings. Dev needs 'unsafe-eval'
    // for React's refresh runtime; production does not get it.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${dev ? " 'unsafe-eval'" : ""}`,
    // Inline styles stay: React's style={{}} props and the printable report
    // use them, and a style cannot run code.
    "style-src 'self' 'unsafe-inline'",
    // data: is the MFA QR codes, drawn in the browser.
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${connect.join(" ")}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

/** Pages that render without a session. */
const PUBLIC_PATHS = ["/login", "/setup"];

/** The session cookie the API sets at sign-in (httpOnly; its value means
 *  nothing here). Its absence is enough to know there is no session, so the
 *  page is never served at all; its presence is checked properly by the
 *  page, which asks the API for a token before it renders. */
const SESSION_COOKIE = "ck_session";

export function middleware(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const isPublic = PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + "/"));
  if (!isPublic && !request.cookies.get(SESSION_COOKIE)?.value) {
    const url = request.nextUrl.clone();
    url.pathname = "/login";
    url.search = `?next=${encodeURIComponent(pathname + search)}`;
    return NextResponse.redirect(url);
  }

  const nonce = btoa(crypto.randomUUID());
  const csp = policy(nonce);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  return response;
}

export const config = {
  matcher: [
    {
      // Static chunks are not documents and carry no nonce; prefetches are
      // answered from the page that will be rendered.
      source: "/((?!api|_next/static|_next/image|favicon.ico|icon.svg).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
