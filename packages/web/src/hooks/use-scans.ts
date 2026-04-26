// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

const STALE_30S = 30 * 1000
const STALE_5M = 5 * 60 * 1000

export function useScans(page = 1) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['scans', page],
    queryFn: () => api.listScans(page),
    enabled: !!user,
    staleTime: STALE_30S,
  })
}

export function useScan(id: string) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['scan', id],
    queryFn: () => api.getScan(id),
    enabled: !!user && !!id,
    staleTime: STALE_30S,
    refetchInterval: (query) => {
      const data = query.state.data
      return data?.status === 'running' ? 3000 : false
    },
  })
}

export function useScanResults(scanId: string) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['scan-results', scanId],
    queryFn: () => api.getScanResults(scanId),
    enabled: !!user && !!scanId,
    staleTime: STALE_5M,
  })
}

export function useScanFindings(scanId: string) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['scan-findings', scanId],
    queryFn: () => api.getScanFindings(scanId),
    enabled: !!user && !!scanId,
    staleTime: STALE_5M,
  })
}

export function useCreateScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: any) => api.createScan(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}
