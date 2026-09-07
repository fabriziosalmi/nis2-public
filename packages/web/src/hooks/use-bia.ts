// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useBia() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ['bia'],
    queryFn: () => api.listBia(),
    enabled: !!user,
    staleTime: 30_000,
  })
}


// --------------------------------------------------------------- mutations
//
// These did not exist. The page rendered bia and offered no way to create,
// edit or remove one, so the module displayed data the product gave no means
// of entering.
function useInvalidateBiaProcess() {
  const qc = useQueryClient()
  return () => {
    qc.invalidateQueries({ queryKey: ['bia'] })
    qc.invalidateQueries({ queryKey: ['bia-matrix'] })
  }
}

export function useCreateBiaProcess() {
  const invalidate = useInvalidateBiaProcess()
  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.createBiaProcess(data),
    onSuccess: invalidate,
  })
}

export function useUpdateBiaProcess() {
  const invalidate = useInvalidateBiaProcess()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      api.updateBiaProcess(id, data),
    onSuccess: invalidate,
  })
}

export function useDeleteBiaProcess() {
  const invalidate = useInvalidateBiaProcess()
  return useMutation({
    mutationFn: (id: string) => api.deleteBiaProcess(id),
    onSuccess: invalidate,
  })
}
