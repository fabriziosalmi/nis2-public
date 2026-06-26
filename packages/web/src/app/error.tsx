// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect } from "react"

/**
 * App Router error boundary. Catches render/runtime errors in any route segment
 * and shows a branded fallback with a retry, instead of Next.js's raw default
 * error screen. Intentionally dependency-light (plain elements + Tailwind, no
 * i18n) so it still renders even if the failure is in shared providers.
 */
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // Surface to the browser console / error tracker; the digest correlates
    // with the server log for the same error.
    console.error(error)
  }, [error])

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 p-6 text-center">
      <h2 className="text-2xl font-semibold">Something went wrong</h2>
      <p className="max-w-md text-sm text-muted-foreground">
        An unexpected error occurred. You can try again — if the problem
        persists, contact your administrator.
      </p>
      {error.digest ? (
        <p className="font-mono text-xs text-muted-foreground/70">
          Ref: {error.digest}
        </p>
      ) : null}
      <button
        onClick={reset}
        className="inline-flex h-10 items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
      >
        Try again
      </button>
    </div>
  )
}
