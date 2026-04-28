// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useAssets(page = 1) {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['assets', page],
    queryFn: () => api.listAssets(page),
    enabled: !!user,
    staleTime: 30_000,
  })
}

export function useCreateAsset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; type: string; target: string; tags?: string[] }) =>
      api.createAsset(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}

export function useDeleteAsset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteAsset(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}

// Update an existing asset. Backend exposes PATCH /api/v1/assets/{id}
// (see app/routers/assets.py:update_asset). Only `name`, `tags`, and
// `is_active` are accepted there — target_type / target_value are
// immutable by design (changing target_value would invalidate every
// historical scan result that references it).
export function useUpdateAsset() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name?: string; tags?: string[]; is_active?: boolean } }) =>
      api.updateAsset(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}
