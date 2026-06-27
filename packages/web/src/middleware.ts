import { NextRequest, NextResponse } from "next/server"

/**
 * Per-request nonce-based Content-Security-Policy (audit fix L12).
 *
 * Next.js App Router emits inline <script> tags for the RSC payload and
 * hydration (self.__next_f.push(...)). A static `script-src 'self'` with no
 * nonce blocks every one of them in production — the page renders but never
 * hydrates, leaving a dead, non-interactive app. (This stayed latent because
 * CI/E2E run in dev mode, where script-src keeps 'unsafe-inline'.)
 *
 * This mints a per-request nonce and hands it to Next via the request's
 * Content-Security-Policy header; Next stamps that nonce onto the scripts it
 * renders. `strict-dynamic` then lets those nonced bootstrap scripts pull in
 * the /_next/static chunks. The same CSP is set on the response.
 *
 * Dev keeps 'unsafe-inline'/'unsafe-eval' (and NO nonce) because React Refresh
 * + webpack HMR compile modules client-side via eval — and because a nonce in
 * the policy makes the browser ignore 'unsafe-inline' entirely, which would
 * break HMR's inline scripts.
 *
 * NOTE on the convention: Next 16.2 logs a deprecation suggesting the `proxy`
 * file convention, but `proxy.ts` is NOT yet recognised by the build in this
 * version (verified: no proxy is emitted, no nonce applied — the codemod ships
 * only on @next/codemod@canary). We therefore stay on the supported, working
 * `middleware` convention and migrate to `proxy` on a future Next upgrade.
 */
export function middleware(request: NextRequest) {
  const isDev = process.env.NODE_ENV !== "production"
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

  // Edge-runtime-safe random nonce (no Node Buffer in the edge runtime).
  let nonce = ""
  if (!isDev) {
    const bytes = new Uint8Array(16)
    crypto.getRandomValues(bytes)
    let bin = ""
    for (const b of bytes) bin += String.fromCharCode(b)
    nonce = btoa(bin)
  }

  const scriptSrc = isDev
    ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    : `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`
  const connectSrc = isDev
    ? `connect-src 'self' ${apiUrl} ws: wss:`
    : `connect-src 'self' ${apiUrl}`

  // style-src keeps 'unsafe-inline': React renders inline `style=` ATTRIBUTES
  // (e.g. severity-badge colors) which cannot carry a nonce, and CSS injection
  // is not script execution. Adding a nonce here would make the browser ignore
  // 'unsafe-inline' and break those attributes.
  const csp = [
    "default-src 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    connectSrc,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ")

  // Next reads the nonce from the request's CSP header and applies it to the
  // scripts it renders; x-nonce lets our own server components read it too.
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set("content-security-policy", csp)
  if (nonce) requestHeaders.set("x-nonce", nonce)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  response.headers.set("content-security-policy", csp)
  return response
}

export const config = {
  matcher: [
    // Run on documents, not static assets / the image optimizer / the API proxy
    // (those don't execute inline scripts). Skip prefetches so a cached RSC
    // prefetch never pins a stale nonce onto a later full navigation.
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
}
