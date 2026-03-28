'use client'

import { useState, useEffect } from 'react'
import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'

interface User {
  id?: string
  email: string
  full_name: string
  role?: string
  org_id?: string
}

interface AuthState {
  token: string | null
  user: User | null
  orgId: string | null
  setAuth: (token: string, user: User, orgId: string) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      user: null,
      orgId: null,
      setAuth: (token, user, orgId) => set({ token, user, orgId }),
      logout: () => set({ token: null, user: null, orgId: null }),
    }),
    {
      name: 'nis2-auth',
      storage: createJSONStorage(() => localStorage),
    }
  )
)

/** Hook that returns true once Zustand has finished hydrating from localStorage. SSR-safe. */
export function useAuthHydrated() {
  const [hydrated, setHydrated] = useState(false)

  useEffect(() => {
    // On client, check if already hydrated or wait for it
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
      // Fallback: just mark as hydrated after a tick
      setHydrated(true)
    }
  }, [])

  return hydrated
}
