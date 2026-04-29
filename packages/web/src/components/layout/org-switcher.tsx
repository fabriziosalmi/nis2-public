// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.4.16 audit B-DRA-02: org switcher component for multi-tenant users.
//
// Visible only when the user has 2+ memberships — single-org users
// never see a UI element they can't act on. Lives in the sidebar
// directly under the logo so it's the first thing a NIS2 consultant
// reaches for when toggling between client tenants.
//
// On switch we:
//   1. POST /auth/switch-org to remint the JWT with the new org_id
//      claim (cookies rotate via Set-Cookie),
//   2. update the local auth-store + clear the TanStack Query cache
//      (handled inside `useSwitchOrg`),
//   3. router.refresh() to re-run server components and pull the
//      new tenant's hydration data.
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { ChevronsUpDown, Check, Loader2, Building2 } from "lucide-react"
import { useTranslations } from "next-intl"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useAuthStore } from "@/stores/auth-store"
import { useOrgs, useSwitchOrg } from "@/hooks/use-orgs"

interface OrgSwitcherProps {
  collapsed: boolean
}

export function OrgSwitcher({ collapsed }: OrgSwitcherProps) {
  const t = useTranslations("orgSwitcher")
  const router = useRouter()
  const orgId = useAuthStore((s) => s.orgId)
  const { data: orgs = [], isLoading } = useOrgs()
  const switchOrg = useSwitchOrg()
  const [open, setOpen] = useState(false)

  // Hide entirely for single-org users — no point in a switcher with
  // one entry. Also hide while the org list is still loading; the
  // sidebar shouldn't show a "loading switcher" placeholder that
  // takes up vertical space and then disappears.
  if (isLoading || orgs.length <= 1) {
    return null
  }

  const currentOrg = orgs.find((o) => o.id === orgId) ?? orgs[0]

  // Container styles match the sidebar's own border conventions so
  // the switcher reads as a first-class element of the sidebar
  // chrome rather than a floating bubble.
  const wrapperClasses = cn(
    "border-b",
    collapsed ? "px-2 py-2" : "px-3 py-3"
  )

  const handleSwitch = async (target: typeof orgs[number]) => {
    if (target.id === orgId) {
      setOpen(false)
      return
    }
    try {
      await switchOrg.mutateAsync(target.id)
      setOpen(false)
      toast.success(t("switchedTo", { name: target.name }))
      // Re-run server components / refetch hydration. The query cache
      // was already cleared inside useSwitchOrg.onSuccess — refresh()
      // triggers any RSC tree to re-hydrate against the new tenant.
      router.refresh()
    } catch (err: any) {
      toast.error(t("switchFailed"), { description: err?.message })
    }
  }

  // Collapsed sidebar: render an icon-only trigger so the switcher
  // doesn't disappear entirely (the user still needs access to it).
  // The dropdown content is full-width at click-time regardless.
  if (collapsed) {
    return (
      <div className={wrapperClasses}>
        <DropdownMenu open={open} onOpenChange={setOpen}>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="mx-auto"
              aria-label={t("trigger", { name: currentOrg.name })}
            >
              {switchOrg.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Building2 className="h-4 w-4" />
              )}
            </Button>
          </DropdownMenuTrigger>
          <SwitcherContent
            orgs={orgs}
            currentOrgId={currentOrg.id}
            onPick={handleSwitch}
            isPending={switchOrg.isPending}
            t={t}
          />
        </DropdownMenu>
      </div>
    )
  }

  return (
    <div className={wrapperClasses}>
      <DropdownMenu open={open} onOpenChange={setOpen}>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            className="w-full justify-between text-left h-auto py-2"
            disabled={switchOrg.isPending}
          >
            <div className="flex items-center gap-2 min-w-0">
              <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
              <div className="flex flex-col min-w-0">
                <span className="text-xs text-muted-foreground leading-tight">
                  {t("currentOrg")}
                </span>
                <span className="text-sm font-medium truncate leading-tight">
                  {currentOrg.name}
                </span>
              </div>
            </div>
            {switchOrg.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin shrink-0" />
            ) : (
              <ChevronsUpDown className="h-4 w-4 shrink-0 opacity-50" />
            )}
          </Button>
        </DropdownMenuTrigger>
        <SwitcherContent
          orgs={orgs}
          currentOrgId={currentOrg.id}
          onPick={handleSwitch}
          isPending={switchOrg.isPending}
          t={t}
        />
      </DropdownMenu>
    </div>
  )
}

// Extracted so the collapsed and expanded triggers share the exact
// same dropdown body. Keeps both branches in sync if we add anything
// (e.g. a "create new organization" footer item later).
function SwitcherContent({
  orgs,
  currentOrgId,
  onPick,
  isPending,
  t,
}: {
  orgs: { id: string; name: string; slug: string }[]
  currentOrgId: string
  // The pick handler can be async (it awaits the switch mutation)
  // OR sync (a noop early-return when the user picks the active
  // org). Allow both with `void | Promise<void>`.
  onPick: (org: { id: string; name: string; slug: string }) => void | Promise<void>
  isPending: boolean
  t: ReturnType<typeof useTranslations>
}) {
  return (
    <DropdownMenuContent align="start" className="w-64">
      <DropdownMenuLabel className="text-xs text-muted-foreground">
        {t("switchTo")}
      </DropdownMenuLabel>
      <DropdownMenuSeparator />
      {orgs.map((o) => (
        <DropdownMenuItem
          key={o.id}
          disabled={isPending}
          onClick={() => onPick(o)}
          className="flex items-center gap-2"
        >
          <div className="flex flex-col min-w-0 flex-1">
            <span className="text-sm font-medium truncate">{o.name}</span>
            <span className="text-xs text-muted-foreground truncate">
              {o.slug}
            </span>
          </div>
          <Check
            className={cn(
              "h-4 w-4 shrink-0",
              o.id === currentOrgId ? "opacity-100" : "opacity-0"
            )}
          />
        </DropdownMenuItem>
      ))}
    </DropdownMenuContent>
  )
}
