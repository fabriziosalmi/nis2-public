// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/keep-public-public
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"

export function useApiKeys() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ["api-keys"],
    queryFn: () => api.listApiKeys(),
    enabled: !!user,
    staleTime: 30_000,
  })
}

export function useCreateApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string }) => api.createApiKey(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  })
}

export function useRevokeApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.revokeApiKey(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  })
}
