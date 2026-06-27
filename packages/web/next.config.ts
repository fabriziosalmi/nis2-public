import type { NextConfig } from 'next'
import createNextIntlPlugin from 'next-intl/plugin'
import path from 'node:path'

const config: NextConfig = {
  output: 'standalone',
  // Dev-only: Next 15.2+/16 blocks cross-origin requests to internal dev
  // resources (notably the /_next/webpack-hmr WebSocket) unless the requesting
  // origin is allow-listed. The docker dev stack is reached at 127.0.0.1:8077 /
  // localhost:8077 through the port-forward, which Next treats as cross-origin —
  // so HMR logged "Blocked cross-origin request to Next.js dev resource" and the
  // hot-reload socket never connected. Allow-listing the dev hosts restores it.
  // Ignored in production builds.
  allowedDevOrigins: ['127.0.0.1', 'localhost'],
  // The repo root has its own package-lock.json (for the VitePress docs
  // build) AND this package has its own. Without pinning the trace root
  // Next 15 prints "We detected multiple lockfiles..." and infers the
  // *repo root* as the workspace, which makes `output: 'standalone'`
  // walk the whole monorepo for required files instead of just this
  // package — slower builds and at least one false-positive missing-
  // file warning per build. Pinning to __dirname keeps file tracing
  // scoped to packages/web.
  outputFileTracingRoot: path.join(__dirname),
  // P1-08 audit fix: removed `typescript: { ignoreBuildErrors: true }`.
  // Globally ignoring TS errors let any type bug pass silently into
  // production — unacceptable for a security compliance platform.
  // Recharts-specific type incompatibilities should be fixed at source
  // (targeted @ts-expect-error on the specific import, or a typed
  // wrapper component) rather than silencing the entire compiler.
  experimental: {
    optimizePackageImports: [
      'lucide-react',
      'recharts',
      '@radix-ui/react-dialog',
      '@radix-ui/react-dropdown-menu',
      '@radix-ui/react-select',
      '@radix-ui/react-tabs',
      '@radix-ui/react-tooltip',
      '@radix-ui/react-avatar',
      '@radix-ui/react-popover',
      'date-fns',
      'class-variance-authority',
    ],
  },
  async rewrites() {
    // Rewrites are evaluated server-side by the Next.js process. When the
    // web service runs inside docker compose, `NEXT_PUBLIC_API_URL` is the
    // browser-facing URL (e.g. http://localhost:8000) which is unreachable
    // from inside the web container. INTERNAL_API_URL is the docker DNS
    // name (e.g. http://api:8000). Outside docker, both fall back to the
    // public URL.
    const target =
      process.env.INTERNAL_API_URL ||
      process.env.NEXT_PUBLIC_API_URL ||
      'http://localhost:8000'
    return [
      {
        source: '/api/v1/:path*',
        destination: `${target}/api/v1/:path*`,
      },
    ]
  },
  async headers() {
    // The Content-Security-Policy is set per-request in src/middleware.ts so it
    // can carry a nonce for Next's inline hydration scripts (App Router emits
    // them; a static `script-src 'self'` blocked them in prod -> no hydration).
    // It must live in exactly one place: a second static CSP here would be
    // intersected with the middleware one and its missing nonce would block the
    // nonced scripts. The static security headers below apply to every route.
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
        ],
      },
    ]
  },
}

const withNextIntl = createNextIntlPlugin('./src/i18n.ts')

export default withNextIntl(config)
