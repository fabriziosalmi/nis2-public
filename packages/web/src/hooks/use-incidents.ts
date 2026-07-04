// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery } from '@tanstack/react-query'
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
