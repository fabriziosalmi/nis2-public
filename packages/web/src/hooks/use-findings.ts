// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useFindings(params: Record<string, string> = {}) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['findings', params],
    queryFn: () => api.listFindings(params),
    enabled: !!user,
    staleTime: 30_000,
  })
}

export function useFindingStats() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['finding-stats'],
    queryFn: () => api.getFindingStats(),
    enabled: !!user,
    staleTime: 60_000,
  })
}

export function useUpdateFinding() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => api.updateFinding(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['finding-stats'] })
    },
  })
}
