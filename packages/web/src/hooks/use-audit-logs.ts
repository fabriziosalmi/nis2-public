// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"

export function useAuditLogs(params: {
  page?: number
  page_size?: number
  action?: string
  resource_type?: string
  user_id?: string
} = {}) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ["audit-logs", params],
    queryFn: () => api.listAuditLogs(params),
    enabled: !!user,
    staleTime: 15_000,
  })
}
