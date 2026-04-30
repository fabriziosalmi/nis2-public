import type { NextConfig } from 'next'
import createNextIntlPlugin from 'next-intl/plugin'
import path from 'node:path'

const config: NextConfig = {
  output: 'standalone',
  // The repo root has its own package-lock.json (for the VitePress docs
  // build) AND this package has its own. Without pinning the trace root
  // Next 15 prints "We detected multiple lockfiles..." and infers the
  // *repo root* as the workspace, which makes `output: 'standalone'`
  // walk the whole monorepo for required files instead of just this
  // package — slower builds and at least one false-positive missing-
  // file warning per build. Pinning to __dirname keeps file tracing
  // scoped to packages/web.
  outputFileTracingRoot: path.join(__dirname),
  typescript: {
    // Recharts dynamic imports have known type incompatibilities with Next.js 15
    ignoreBuildErrors: true,
  },
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
    // Next.js dev mode (React Refresh + webpack HMR) compiles modules client-
    // side via `new Function()` / `eval`, which a strict CSP without
    // 'unsafe-eval' blocks. We only loosen the policy in development; the
    // production build is fully pre-compiled and keeps the tight policy.
    const isDev = process.env.NODE_ENV !== 'production'
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
    const scriptSrc = isDev
      ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
      : "script-src 'self' 'unsafe-inline'"
    const connectSrc = isDev
      ? `connect-src 'self' ${apiUrl} ws: wss:`
      : `connect-src 'self' ${apiUrl}`
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
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              scriptSrc,
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "font-src 'self' https://fonts.gstatic.com",
              "img-src 'self' data: blob: https:",
              connectSrc,
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join('; '),
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
