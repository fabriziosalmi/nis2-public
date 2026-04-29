// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuthStore, useAuthHydrated } from "@/stores/auth-store"
import { Sidebar } from "@/components/layout/sidebar"
import { Header } from "@/components/layout/header"
import { CommandPalette } from "@/components/layout/command-palette"

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const hydrated = useAuthHydrated()

  useEffect(() => {
    if (hydrated && !user) {
      router.replace("/login")
    }
  }, [hydrated, user, router])

  if (!hydrated) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    )
  }

  if (!user) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="animate-pulse text-muted-foreground">Redirecting...</div>
      </div>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6 lg:p-8">{children}</main>
      </div>
      {/* v2.4.17 audit O-DRA-01: Cmd+K palette. Mounted at the
          dashboard layout level so the keyboard shortcut listener
          attaches once and the dialog is reachable from every
          authenticated screen. */}
      <CommandPalette />
    </div>
  )
}
