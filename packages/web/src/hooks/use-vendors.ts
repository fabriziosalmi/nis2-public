// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useVendors() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['vendors'],
    queryFn: () => api.listVendors(),
    enabled: !!user,
    staleTime: 30_000,
  })
}

export function useVendorStats() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['vendor-stats'],
    queryFn: () => api.getVendorStats(),
    enabled: !!user,
    staleTime: 30_000,
  })
}


// --------------------------------------------------------------- mutations
//
// These did not exist. The page rendered vendors and offered no way to create,
// edit or remove one, so the module displayed data the product gave no means
// of entering.
function useInvalidateVendor() {
  const qc = useQueryClient()
  return () => {
    qc.invalidateQueries({ queryKey: ['vendors'] })
    qc.invalidateQueries({ queryKey: ['vendor-stats'] })
  }
}

export function useCreateVendor() {
  const invalidate = useInvalidateVendor()
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.createVendor(data),
    onSuccess: invalidate,
  })
}

export function useUpdateVendor() {
  const invalidate = useInvalidateVendor()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      api.updateVendor(id, data),
    onSuccess: invalidate,
  })
}

export function useDeleteVendor() {
  const invalidate = useInvalidateVendor()
  return useMutation({
    mutationFn: (id: string) => api.deleteVendor(id),
    onSuccess: invalidate,
  })
}
