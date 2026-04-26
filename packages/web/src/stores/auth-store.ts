// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
'use client'

import { useState, useEffect } from 'react'
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

import { api } from '@/lib/api-client'

interface User {
  id?: string
  email: string
  full_name: string
  role?: string
  org_id?: string
}

// We persist only `user` and `orgId` for fast UI hydration on page load.
// Neither is a secret — both are visible inside the dashboard anyway. The
// access/refresh tokens live in httpOnly cookies and never touch JS state.
interface AuthState {
  user: User | null
  orgId: string | null
  setAuth: (user: User, orgId: string | null) => void
  logout: () => Promise<void>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      orgId: null,
      setAuth: (user, orgId) => set({ user, orgId }),
      logout: async () => {
        try {
          await api.logout()
        } catch {
          // Even if the server call fails, drop local state.
        }
        set({ user: null, orgId: null })
      },
    }),
    {
      // v2 = post-cookie-auth schema. v1 stored a JWT in the `token` field;
      // dropping the key invalidates stale local state from older builds.
      name: 'nis2-auth-v2',
      storage: createJSONStorage(() => localStorage),
    }
  )
)

/** Hook that returns true once Zustand has finished hydrating from localStorage. SSR-safe. */
export function useAuthHydrated() {
  const [hydrated, setHydrated] = useState(false)

  useEffect(() => {
    try {
      if (useAuthStore.persist.hasHydrated()) {
        setHydrated(true)
      } else {
        const unsub = useAuthStore.persist.onFinishHydration(() => {
          setHydrated(true)
        })
        return () => unsub()
      }
    } catch {
      setHydrated(true)
    }
  }, [])

  return hydrated
}
