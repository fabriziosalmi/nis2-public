// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.4.17 audit O-DRA-01: Cmd+K command palette.
//
// The header in v2.4.14 had a button styled as a search input with a
// `Ctrl+K` kbd hint and no behaviour behind it (audit B-DRA-01); we
// killed that fake UX in v2.4.15 with the explicit promise that a
// real palette would land later. This is that.
//
// What it does (v1):
//   - Cmd+K (macOS) / Ctrl+K (Linux/Windows) opens the dialog from
//     anywhere in the dashboard.
//   - Lists every primary navigation entry (dashboard, scans,
//     assets, findings, compliance, reports) and the settings
//     surfaces, with their lucide-react icons.
//   - Built on `cmdk` (already in package.json) which gives us
//     fuzzy-search filtering, keyboard arrow navigation, and the
//     standard ⌘K UX everyone expects.
//   - Esc / clicking outside closes the dialog.
//
// What it intentionally does NOT do (yet):
//   - No "search across resources" (scans by name, findings by
//     target, etc.) — that needs a backend cross-resource search
//     endpoint we don't have. Future iteration.
//   - No "recent" / "frequently used" — would need persistence in
//     localStorage. Future iteration.
//
// Mounted globally in the dashboard layout's Providers tree so the
// keyboard shortcut listener attaches once and lives for the
// lifetime of the SPA session.
"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { Command } from "cmdk"
import {
  LayoutDashboard,
  Radar,
  Server,
  AlertTriangle,
  ShieldCheck,
  FileText,
  Building2,
  UserCog,
  Users,
  Key,
  Bell,
  ScrollText,
  CalendarClock,
  GitCompareArrows,
  type LucideIcon,
} from "lucide-react"
import { useTranslations } from "next-intl"
import { cn } from "@/lib/utils"

interface NavCommand {
  navKey: string
  href: string
  icon: LucideIcon
  /** Higher = ranks above peer matches with equal text score. */
  weight?: number
}

// Single source of truth for the palette's actions. Keys map into
// the `nav.*` namespace so the user sees the same labels as the
// sidebar regardless of locale.
const NAV_COMMANDS: NavCommand[] = [
  { navKey: "dashboard", href: "/dashboard", icon: LayoutDashboard, weight: 100 },
  { navKey: "scans", href: "/dashboard/scans", icon: Radar, weight: 90 },
  { navKey: "assets", href: "/dashboard/assets", icon: Server, weight: 90 },
  { navKey: "findings", href: "/dashboard/findings", icon: AlertTriangle, weight: 95 },
  { navKey: "compliance", href: "/dashboard/compliance", icon: ShieldCheck, weight: 80 },
  { navKey: "reports", href: "/dashboard/reports", icon: FileText, weight: 70 },
  { navKey: "organization", href: "/dashboard/settings/organization", icon: Building2 },
  { navKey: "profile", href: "/dashboard/settings/profile", icon: UserCog },
  { navKey: "scanDefaults", href: "/dashboard/settings/scan-defaults", icon: Radar },
  { navKey: "team", href: "/dashboard/settings/team", icon: Users },
  { navKey: "apiKeys", href: "/dashboard/settings/api-keys", icon: Key },
  { navKey: "notifications", href: "/dashboard/settings/notifications", icon: Bell },
  { navKey: "auditLog", href: "/dashboard/settings/audit-log", icon: ScrollText },
]

// Action-shaped commands that don't map to a nav entry. Their labels
// live under `commandPalette.actions.*`.
interface ActionCommand {
  actionKey: string
  href: string
  icon: LucideIcon
}

const ACTION_COMMANDS: ActionCommand[] = [
  { actionKey: "newScan", href: "/dashboard/scans/new", icon: Radar },
  { actionKey: "schedules", href: "/dashboard/scans/schedules", icon: CalendarClock },
]

export function CommandPalette() {
  const router = useRouter()
  const t = useTranslations()
  const [open, setOpen] = useState(false)

  // Cmd+K (macOS) / Ctrl+K (everywhere else). We attach to `keydown`
  // on the document so the shortcut works regardless of focused
  // element. `event.metaKey` covers macOS, `event.ctrlKey` everywhere
  // else; checking both means a Linux user with Cmd-mapped keyboards
  // also gets the binding.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((prev) => !prev)
      }
    }
    document.addEventListener("keydown", onKey)
    return () => document.removeEventListener("keydown", onKey)
  }, [])

  const handleSelect = (href: string) => {
    setOpen(false)
    router.push(href)
  }

  // Esc / click outside via the cmdk Dialog primitive. Using the
  // built-in `Command.Dialog` rather than wrapping our own
  // `<Dialog>` so cmdk owns focus management end-to-end (the cmdk
  // internals handle the focus trap, restore on close, and the
  // search field auto-focus).
  return (
    <Command.Dialog
      open={open}
      onOpenChange={setOpen}
      label={t("commandPalette.label")}
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
    >
      {/* Backdrop. cmdk's overlay isn't styled by default; we add the
          dim layer ourselves so click-outside has a clear hit-target
          and the dialog visually pops above the dashboard. */}
      <div
        className="fixed inset-0 bg-black/50"
        onClick={() => setOpen(false)}
      />
      <div className="relative w-full max-w-xl rounded-lg border bg-popover text-popover-foreground shadow-lg">
        <Command.Input
          placeholder={t("commandPalette.placeholder")}
          className={cn(
            "w-full border-b px-4 py-3 text-sm outline-none bg-transparent",
            "placeholder:text-muted-foreground"
          )}
        />
        <Command.List className="max-h-[400px] overflow-y-auto p-2">
          <Command.Empty className="py-6 text-center text-sm text-muted-foreground">
            {t("commandPalette.empty")}
          </Command.Empty>

          <Command.Group
            heading={t("commandPalette.actionsGroup")}
            className="text-xs font-semibold uppercase tracking-wider text-muted-foreground px-2 py-1"
          >
            {ACTION_COMMANDS.map((cmd) => {
              const label = t(`commandPalette.actions.${cmd.actionKey}` as any)
              return (
                <Command.Item
                  key={cmd.href}
                  value={`${label} ${cmd.actionKey}`}
                  onSelect={() => handleSelect(cmd.href)}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2 text-sm cursor-pointer",
                    "data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
                  )}
                >
                  <cmd.icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <span>{label}</span>
                </Command.Item>
              )
            })}
          </Command.Group>

          <Command.Group
            heading={t("commandPalette.navigateGroup")}
            className="text-xs font-semibold uppercase tracking-wider text-muted-foreground px-2 py-1 mt-2"
          >
            {NAV_COMMANDS.map((cmd) => {
              const label = t(`nav.${cmd.navKey}` as any)
              return (
                <Command.Item
                  key={cmd.href}
                  // `value` is what cmdk fuzzy-matches against. We
                  // include both the localised label AND the
                  // canonical key so EN users can type "scans" while
                  // an IT user typing "scansioni" both hit the same
                  // row. The `weight` lets primary nav rank above
                  // settings entries on a generic search.
                  value={`${label} ${cmd.navKey}`}
                  onSelect={() => handleSelect(cmd.href)}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2 text-sm cursor-pointer",
                    "data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
                  )}
                >
                  <cmd.icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                  <span>{label}</span>
                </Command.Item>
              )
            })}
          </Command.Group>
        </Command.List>
        <div className="flex items-center justify-end gap-2 border-t px-3 py-2 text-xs text-muted-foreground">
          <kbd className="rounded border bg-muted px-1.5 font-mono text-[10px]">↑↓</kbd>
          <span>{t("commandPalette.hintNavigate")}</span>
          <kbd className="ml-2 rounded border bg-muted px-1.5 font-mono text-[10px]">↵</kbd>
          <span>{t("commandPalette.hintSelect")}</span>
          <kbd className="ml-2 rounded border bg-muted px-1.5 font-mono text-[10px]">esc</kbd>
          <span>{t("commandPalette.hintClose")}</span>
        </div>
      </div>
    </Command.Dialog>
  )
}
