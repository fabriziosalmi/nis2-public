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

/** Record that an Art. 23 obligation was filed with CSIRT Italia.
 *
 *  Submission happens on csirt.gov.it and the platform cannot observe it, so
 *  the operator records it. Until this existed the three `*_sent_at` columns
 *  were read by the deadline task, by the API and by the countdown, and written
 *  by nothing: filing the Early Warning on time did not stop the breach alerts
 *  for it. */
export function useRecordSubmission() {
  const invalidate = useInvalidateIncident()
  return useMutation({
    mutationFn: ({
      id,
      obligation,
      csirtReferenceId,
    }: {
      id: string
      obligation: 'early_warning' | 'notification' | 'final_report'
      csirtReferenceId?: string
    }) => api.recordIncidentSubmission(id, obligation, csirtReferenceId),
    onSuccess: invalidate,
  })
}

/** The CSIRT "Red Button". Declares the incident — starting the clocks the
 *  monitor watches — and returns the Early Warning payload. */
export function useCsirtEmergency() {
  const invalidate = useInvalidateIncident()
  return useMutation({
    mutationFn: (data: {
      what_happened: string
      affected_services: string
      is_ongoing: boolean
      estimated_users_affected?: number | null
    }) => api.csirtEmergency(data),
    onSuccess: invalidate,
  })
}
