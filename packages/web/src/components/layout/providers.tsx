// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ThemeProvider } from "next-themes"
import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { toast } from "sonner"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { SESSION_EXPIRED_EVENT } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"

/**
 * Listens for the api-client's session-expired signal (fires when a
 * protected request 401s AND the silent refresh-token attempt also
 * fails). On signal: clear local auth state and redirect to /login
 * with a flag so the login page can show a "session expired, please
 * sign in again" notice instead of just blanking the form. Without
 * this, the dashboard stayed navigable but every mutation silently
 * failed — Davide observed this on a stale tab after ~30 min.
 */
function SessionExpiredHandler() {
  const router = useRouter()
  useEffect(() => {
    const handler = () => {
      // Local clear only — server-side the session is already dead, no
      // point firing /auth/logout (and that endpoint would itself need
      // a valid token, which we don't have).
      useAuthStore.setState({ user: null, orgId: null })
      toast.error("Session expired", {
        description: "Please sign in again to continue.",
      })
      router.replace("/login?session=expired")
    }
    window.addEventListener(SESSION_EXPIRED_EVENT, handler)
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, handler)
  }, [router])
  return null
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 60 * 1000,
            gcTime: 5 * 60 * 1000,
            // Don't retry 401s — the api-client's refresh dance already
            // handled (or failed to handle) auth before we ever get here.
            // A blind retry just doubles the failed-request log noise.
            retry: (failureCount, error: any) =>
              failureCount < 1 && error?.message !== "Session expired",
            refetchOnWindowFocus: false,
          },
        },
      })
  )

  return (
    // ThemeProvider wraps everything else so the entire tree (including
    // toasts) follows the active theme. `attribute="class"` toggles the
    // `dark` class on <html>, which Tailwind's `dark:` variants pick up.
    // `defaultTheme="system"` honours OS preference; users override via
    // the toggle in the header. `disableTransitionOnChange` avoids the
    // half-second style flash when switching mode.
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
    >
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <SessionExpiredHandler />
          {children}
          <Toaster position="top-right" richColors closeButton />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
