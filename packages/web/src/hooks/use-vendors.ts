// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useVendors() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['vendors'],
    queryFn: () => api.listVendors(),
    enabled: !!user,
    staleTime: 30_000,
  })
}

export function useVendorStats() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['vendor-stats'],
    queryFn: () => api.getVendorStats(),
    enabled: !!user,
    staleTime: 30_000,
  })
}
