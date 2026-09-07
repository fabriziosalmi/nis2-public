// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { useAuthStore } from '@/stores/auth-store'

const KEY = ['notification-channels']

export function useNotificationChannels() {
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: KEY,
    queryFn: () => api.listNotificationChannels(),
    enabled: !!user,
  })
}

export function useCreateNotificationChannel() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Parameters<typeof api.createNotificationChannel>[0]) =>
      api.createNotificationChannel(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useUpdateNotificationChannel() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) =>
      api.updateNotificationChannel(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useDeleteNotificationChannel() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.deleteNotificationChannel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  })
}

export function useTestNotificationChannel() {
  return useMutation({
    mutationFn: (id: string) => api.testNotificationChannel(id),
  })
}
