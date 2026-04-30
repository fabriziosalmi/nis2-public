// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useTranslations } from "next-intl"
import { useAuthStore, useAuthHydrated } from "@/stores/auth-store"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { CommandPalette } from "@/components/layout/command-palette"

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const hydrated = useAuthHydrated()
  const tc = useTranslations("common")
  const ta = useTranslations("a11y")

  useEffect(() => {
    if (hydrated && !user) {
      router.replace("/login")
    }
  }, [hydrated, user, router])

  // v2.4.23 audit a11y-08: loading + redirect splash screens get a
  // proper status role + aria-live so screen readers actually
  // announce the state change instead of seeing a silent unlabelled
  // pulsing div.
  if (!hydrated) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div role="status" aria-live="polite" className="animate-pulse text-muted-foreground">
          {tc("loading")}
        </div>
      </div>
    )
  }

  if (!user) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div role="status" aria-live="polite" className="animate-pulse text-muted-foreground">
          {tc("redirecting")}
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      {/* v2.4.23 audit a11y-10 (WCAG SC 2.4.1 Bypass Blocks): a
          skip-to-content link is the first focusable element on the
          page so a keyboard / screen-reader user can jump past the
          (long) sidebar to the main panel without tabbing through
          ~17 nav links. The `sr-only focus:not-sr-only` Tailwind
          pattern keeps it visually hidden until focused, then pops
          it on top of the layout. */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-background focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-foreground focus:shadow-lg focus:outline-none focus:ring-2 focus:ring-ring"
      >
        {ta("skipToContent")}
      </a>
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <main id="main-content" tabIndex={-1} className="flex-1 overflow-y-auto p-6 lg:p-8">
          {children}
        </main>
      </div>
      {/* v2.4.17 audit O-DRA-01: Cmd+K palette. Mounted at the
          dashboard layout level so the keyboard shortcut listener
          attaches once and the dialog is reachable from every
          authenticated screen. */}
      <CommandPalette />
    </div>
  )
}
