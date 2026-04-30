// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"

const STALE_30S = 30 * 1000

/**
 * Members of the active organization. The org_id is read from the
 * auth store (mirrors the JWT org_id claim that get_current_org
 * resolves on the server). The query is keyed on orgId so a future
 * org-switcher invalidates the right cache.
 */
export function useMembers() {
  const orgId = useAuthStore((s) => s.orgId)
  const user = useAuthStore((s) => s.user)
  return useQuery({
    queryKey: ["members", orgId],
    queryFn: () => api.listMembers(orgId!),
    enabled: !!user && !!orgId,
    staleTime: STALE_30S,
  })
}

export function useInviteMember() {
  const qc = useQueryClient()
  const orgId = useAuthStore((s) => s.orgId)
  return useMutation({
    mutationFn: (data: { email: string; role: string }) =>
      api.inviteMember(orgId!, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members", orgId] }),
  })
}

export function useUpdateMemberRole() {
  const qc = useQueryClient()
  const orgId = useAuthStore((s) => s.orgId)
  return useMutation({
    mutationFn: ({ memberId, role }: { memberId: string; role: string }) =>
      api.updateMemberRole(orgId!, memberId, role),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members", orgId] }),
  })
}

export function useRemoveMember() {
  const qc = useQueryClient()
  const orgId = useAuthStore((s) => s.orgId)
  return useMutation({
    mutationFn: (memberId: string) => api.removeMember(orgId!, memberId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members", orgId] }),
  })
}
