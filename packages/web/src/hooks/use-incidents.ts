// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

// Art. 23 incident-deadline monitor. The live countdown is computed
// client-side from the deadline ISO timestamps (see the page), so the
// query itself just needs to keep the row set fresh.
export function useIncidentMonitor(onlyOpen = false) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['incident-monitor', onlyOpen],
    queryFn: () => api.listIncidentMonitor(onlyOpen),
    enabled: !!user,
    staleTime: 30_000,
  })
}


// --------------------------------------------------------------- mutations
//
// These did not exist. The page rendered incidents and offered no way to create,
// edit or remove one, so the module displayed data the product gave no means
// of entering.
function useInvalidateIncident() {
  const qc = useQueryClient()
  return () => {
    qc.invalidateQueries({ queryKey: ['incidents'] })
    qc.invalidateQueries({ queryKey: ['incident-monitor'] })
  }
}

export function useCreateIncident() {
  const invalidate = useInvalidateIncident()
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.createIncident(data),
    onSuccess: invalidate,
  })
}

export function useUpdateIncident() {
  const invalidate = useInvalidateIncident()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      api.updateIncident(id, data),
    onSuccess: invalidate,
  })
}

export function useDeleteIncident() {
  const invalidate = useInvalidateIncident()
  return useMutation({
    mutationFn: (id: string) => api.deleteIncident(id),
    onSuccess: invalidate,
  })
}
