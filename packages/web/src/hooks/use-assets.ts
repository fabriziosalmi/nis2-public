import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

export function useAssets(page = 1) {
  const token = useAuthStore((s) => s.token)
  return useQuery({
    queryKey: ['assets', page],
    queryFn: () => api.listAssets(token!, page),
    enabled: !!token,
    staleTime: 30_000,
  })
}

export function useCreateAsset() {
  const token = useAuthStore((s) => s.token)
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; type: string; target: string; tags?: string[] }) =>
      api.createAsset(token!, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}

export function useDeleteAsset() {
  const token = useAuthStore((s) => s.token)
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteAsset(token!, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
  })
}
