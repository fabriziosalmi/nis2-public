// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.4.16 audit B-DRA-02: hooks behind the org switcher.
//
// `useOrgs` returns every organization the current user has membership
// in (via GET /api/v1/organizations). Used by the sidebar's
// <OrgSwitcher> to know whether to render at all (single-org users
// don't get a switcher) and to populate the dropdown.
//
// `useSwitchOrg` performs the switch. After the API rotates the
// cookies and returns the new TokenResponse, we:
//   1. update the auth-store's `orgId` (so `useScans` etc. re-key
//      their queries on the new org),
//   2. clear the entire TanStack Query cache — every list / detail
//      query is RLS-scoped on the server, so stale results from the
//      previous tenant must not leak into the new view,
//   3. let the caller decide what to do next (typically: navigate
//      to /dashboard so the UI hydrates with the new tenant).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"

const STALE_60S = 60 * 1000

// Trimmed view of the OrgResponse — the switcher only needs id/name/slug
// to render and act on. Other fields (plan, settings, max_scans_per_month)
// arrive in the wire response but we don't strongly type them here so a
// future BE field addition doesn't tighten this client-side contract.
interface OrgRow {
  id: string
  name: string
  slug: string
}

/** Fetch every org the authed user belongs to. Cached for 60s. */
export function useOrgs() {
  const user = useAuthStore((s) => s.user)
  return useQuery<OrgRow[]>({
    queryKey: ["orgs", user?.id],
    queryFn: () => api.listOrgs(),
    enabled: !!user,
    staleTime: STALE_60S,
  })
}

/** Switch active organization. Caller awaits the mutation; on success
 *  the auth store has the new org_id and the query cache is cleared. */
export function useSwitchOrg() {
  const setAuth = useAuthStore((s) => s.setAuth)
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (organizationId: string) => api.switchOrg(organizationId),
    onSuccess: (resp) => {
      // The API set the cookies via Set-Cookie; we just sync the
      // local auth-store with the new org_id. The user object is
      // unchanged (still the same person), but we re-assert it to
      // keep the persist middleware in sync.
      if (resp?.user && resp?.org_id) {
        setAuth(resp.user, resp.org_id)
      }
      // Nuke every query — every screen's data is RLS-scoped on the
      // org_id claim, so anything cached before the switch is now
      // for the wrong tenant. clear() is heavier than
      // invalidateQueries, but invalidating page-by-page would race
      // with components reading the stale data on the same render.
      qc.clear()
    },
  })
}

/**
 * v2.4.18: self-serve org creation. The mutation returns the new
 * `OrgRow`; caller is expected to invalidate / refetch the orgs
 * list (we do that here automatically) and optionally switch into
 * the new org via `useSwitchOrg`.
 */
export function useCreateOrg() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (name: string) => api.createOrg({ name }),
    onSuccess: () => {
      // The orgs list is keyed by user id (see useOrgs above); the
      // new org belongs to the current user, so invalidating that
      // exact query refetches and refreshes the switcher dropdown.
      qc.invalidateQueries({ queryKey: ["orgs"] })
    },
  })
}
