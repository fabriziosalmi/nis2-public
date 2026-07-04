// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useGovernance(params: Record<string, string> = {}) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['governance', params],
    queryFn: () => api.listGovernance(params),
    enabled: !!user,
    staleTime: 30_000,
  })
}

export function useGovernanceScore() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['governance-score'],
    queryFn: () => api.getGovernanceScore(),
    enabled: !!user,
    staleTime: 30_000,
  })
}

function invalidateGovernance(qc: ReturnType<typeof useQueryClient>) {
  qc.invalidateQueries({ queryKey: ['governance'] })
  qc.invalidateQueries({ queryKey: ['governance-score'] })
}

// The scanner-findings → checklist bridge. Escalates not_started items to
// in_progress and attaches finding evidence.
export function useSyncRisk() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.syncRisk(),
    onSuccess: () => invalidateGovernance(qc),
  })
}

export function useSeedGovernance() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => api.seedGovernance(),
    onSuccess: () => invalidateGovernance(qc),
  })
}

export function useUpdateGovernanceItem() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => api.updateGovernanceItem(id, data),
    onSuccess: () => invalidateGovernance(qc),
  })
}
