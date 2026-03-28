"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuthStore, useAuthHydrated } from "@/stores/auth-store"

export default function Home() {
  const router = useRouter()
  const token = useAuthStore((s) => s.token)
  const hydrated = useAuthHydrated()

  useEffect(() => {
    if (!hydrated) return
    if (token) {
      router.replace("/dashboard")
    } else {
      router.replace("/login")
    }
  }, [hydrated, token, router])

  return (
    <div className="flex h-screen items-center justify-center">
      <div className="animate-pulse text-muted-foreground">Loading...</div>
    </div>
  )
}
