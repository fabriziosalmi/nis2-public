// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuthStore, useAuthHydrated } from "@/stores/auth-store"

export default function Home() {
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const hydrated = useAuthHydrated()

  useEffect(() => {
    if (!hydrated) return
    router.replace(user ? "/dashboard" : "/login")
  }, [hydrated, user, router])

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="animate-pulse text-muted-foreground">Loading...</div>
    </div>
  )
}
