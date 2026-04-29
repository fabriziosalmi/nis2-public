// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.4.16 audit B-DRA-02: org switcher component for multi-tenant users.
// v2.4.18 follow-up: also hosts the "Create new organization" entry
// point so a user with just one org can spin up a second tenant
// without going hunting for the action elsewhere in the UI.
//
// Visibility rules (v2.4.18):
//   - User has 0 orgs (transient hydration window): render nothing.
//   - User has 1 org: render the switcher trigger so the "Create new
//     organization" footer is reachable. The dropdown shows their
//     single org with a check mark, plus the create-new item.
//   - User has 2+ orgs: same as before — full switcher.
//
// On switch we:
//   1. POST /auth/switch-org to remint the JWT with the new org_id
//      claim (cookies rotate via Set-Cookie),
//   2. update the local auth-store + clear the TanStack Query cache
//      (handled inside `useSwitchOrg`),
//   3. router.refresh() to re-run server components and pull the
//      new tenant's hydration data.
//
// On create-new we:
//   1. POST /api/v1/organizations (returns the new org row),
//   2. invalidate the orgs query (the dropdown refreshes),
//   3. immediately switch into the new org so the user lands in the
//      tenant they just created — same UX as Vercel/Linear/etc.
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import {
  ChevronsUpDown,
  Check,
  Loader2,
  Building2,
  Plus,
} from "lucide-react"
import { useTranslations } from "next-intl"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useAuthStore } from "@/stores/auth-store"
import { useOrgs, useSwitchOrg, useCreateOrg } from "@/hooks/use-orgs"

interface OrgSwitcherProps {
  collapsed: boolean
}

// Zod messages are i18n KEYS resolved via t(error.message) at render
// time — same pattern as login / register / profile. Keys live in
// the `orgSwitcher` namespace.
const createOrgSchema = z.object({
  name: z.string().min(1, "createNameRequired").max(256),
})

type CreateOrgForm = z.infer<typeof createOrgSchema>

export function OrgSwitcher({ collapsed }: OrgSwitcherProps) {
  const t = useTranslations("orgSwitcher")
  const router = useRouter()
  const orgId = useAuthStore((s) => s.orgId)
  const { data: orgs = [], isLoading } = useOrgs()
  const switchOrg = useSwitchOrg()
  const createOrg = useCreateOrg()
  const [open, setOpen] = useState(false)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CreateOrgForm>({ resolver: zodResolver(createOrgSchema) })

  // Hide while the org list is still loading; the sidebar shouldn't
  // show a "loading switcher" placeholder that takes up vertical
  // space and then disappears. Once loaded we always render the
  // switcher (even for single-org users) so the create-new entry
  // point stays reachable.
  if (isLoading || orgs.length === 0) {
    return null
  }

  const currentOrg = orgs.find((o) => o.id === orgId) ?? orgs[0]

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
      router.refresh()
    } catch (err: any) {
      toast.error(t("switchFailed"), { description: err?.message })
    }
  }

  const handleCreateClick = () => {
    setOpen(false)
    setCreateDialogOpen(true)
  }

  const onCreateSubmit = async (data: CreateOrgForm) => {
    try {
      const newOrg = await createOrg.mutateAsync(data.name)
      // Close the dialog FIRST so the user sees the toast and the
      // switch happens against a clean UI tree. The query cache
      // invalidation in useCreateOrg has already refreshed the
      // dropdown's org list in the background.
      reset()
      setCreateDialogOpen(false)
      toast.success(t("createSuccess", { name: newOrg.name }))
      // Auto-switch into the newly-created org. Mirrors the UX of
      // Vercel / Linear / etc. — the user just spun up a tenant,
      // they almost certainly want to land in it. If the switch
      // itself fails (very rare: rate limit or network blip), we
      // don't block — the org exists and the user can switch
      // manually from the dropdown.
      try {
        await switchOrg.mutateAsync(newOrg.id)
        router.refresh()
      } catch {
        // swallow: org was created successfully, switch is best-effort
      }
    } catch (err: any) {
      toast.error(t("createFailed"), { description: err?.message })
    }
  }

  const triggerCommon = (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      {collapsed ? (
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
      ) : (
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
      )}
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel className="text-xs text-muted-foreground">
          {t("switchTo")}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {orgs.map((o) => (
          <DropdownMenuItem
            key={o.id}
            disabled={switchOrg.isPending}
            onClick={() => handleSwitch(o)}
            className="flex items-center gap-2"
          >
            <div className="flex flex-col min-w-0 flex-1">
              <span className="text-sm font-medium truncate">{o.name}</span>
              <span className="text-xs text-muted-foreground truncate">{o.slug}</span>
            </div>
            <Check
              className={cn(
                "h-4 w-4 shrink-0",
                o.id === currentOrg.id ? "opacity-100" : "opacity-0"
              )}
            />
          </DropdownMenuItem>
        ))}
        {/* v2.4.18: footer item to create a new organization. Lives
            below a separator so it visually reads as an action,
            distinct from the list-of-orgs above. */}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={handleCreateClick}
          className="flex items-center gap-2 text-primary focus:text-primary"
        >
          <Plus className="h-4 w-4 shrink-0" />
          <span className="text-sm font-medium">{t("createOrg")}</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )

  return (
    <div className={wrapperClasses}>
      {triggerCommon}

      {/* v2.4.18: create-new-organization dialog. Single name input
          since the slug is derived server-side; if/when we expose
          slug or plan as user-editable, this form grows. */}
      <Dialog
        open={createDialogOpen}
        onOpenChange={(o) => {
          if (!o) reset()
          setCreateDialogOpen(o)
        }}
      >
        <DialogContent>
          <form onSubmit={handleSubmit(onCreateSubmit)}>
            <DialogHeader>
              <DialogTitle>{t("createTitle")}</DialogTitle>
              <DialogDescription>{t("createDescription")}</DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="orgName">{t("createNameLabel")}</Label>
                <Input
                  id="orgName"
                  placeholder={t("createNamePlaceholder")}
                  autoFocus
                  {...register("name")}
                />
                {errors.name && (
                  <p className="text-xs text-destructive">
                    {t(errors.name.message as any)}
                  </p>
                )}
              </div>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  reset()
                  setCreateDialogOpen(false)
                }}
              >
                {t("createCancel")}
              </Button>
              <Button
                type="submit"
                disabled={createOrg.isPending || switchOrg.isPending}
              >
                {(createOrg.isPending || switchOrg.isPending) && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                {t("createSubmit")}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
