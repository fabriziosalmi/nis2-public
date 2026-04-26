// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useFindings(params: Record<string, string> = {}) {
  const token = useAuthStore((s) => s.token)
  return useQuery({
    queryKey: ['findings', params],
    queryFn: () => api.listFindings(token!, params),
    enabled: !!token,
    staleTime: 30_000,
  })
}

export function useFindingStats() {
  const token = useAuthStore((s) => s.token)
  return useQuery({
    queryKey: ['finding-stats'],
    queryFn: () => api.getFindingStats(token!),
    enabled: !!token,
    staleTime: 60_000,
  })
}

export function useUpdateFinding() {
  const token = useAuthStore((s) => s.token)
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => api.updateFinding(token!, id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['finding-stats'] })
    },
  })
}
