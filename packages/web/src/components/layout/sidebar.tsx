// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useTranslations } from "next-intl"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import {
  LayoutDashboard,
  Radar,
  Server,
  AlertTriangle,
  ShieldCheck,
  FileText,
  Settings,
  Users,
  Key,
  Bell,
  ScrollText,
  Building2,
  UserCog,
  LogOut,
  Menu,
  X,
  ChevronLeft,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { Logo } from "@/components/brand/logo"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { OrgSwitcher } from "@/components/layout/org-switcher"
import { useAuthStore } from "@/stores/auth-store"
import { useFindingStats } from "@/hooks/use-findings"
import { useEffect, useState } from "react"

const mainNavKeys = [
  { key: "dashboard", href: "/dashboard", icon: LayoutDashboard },
  { key: "scans", href: "/dashboard/scans", icon: Radar },
  { key: "assets", href: "/dashboard/assets", icon: Server },
  { key: "findings", href: "/dashboard/findings", icon: AlertTriangle },
  { key: "compliance", href: "/dashboard/compliance", icon: ShieldCheck },
  { key: "reports", href: "/dashboard/reports", icon: FileText },
]

const settingsNavKeys = [
  { key: "organization", href: "/dashboard/settings/organization", icon: Building2 },
  { key: "profile", href: "/dashboard/settings/profile", icon: UserCog },
  { key: "scanDefaults", href: "/dashboard/settings/scan-defaults", icon: Radar },
  { key: "team", href: "/dashboard/settings/team", icon: Users },
  { key: "apiKeys", href: "/dashboard/settings/api-keys", icon: Key },
  { key: "notifications", href: "/dashboard/settings/notifications", icon: Bell },
  { key: "auditLog", href: "/dashboard/settings/audit-log", icon: ScrollText },
]

export function Sidebar() {
  const pathname = usePathname()
  const router = useRouter()
  const { user, logout } = useAuthStore()
  const t = useTranslations()
  // v2.4.23 audit a11y namespace for accessibility-only strings
  // (skip link, button labels for icon-only buttons, etc.) so the
  // nav i18n stays uncluttered.
  const ta = useTranslations("a11y")
  // v2.4.17 audit O-DRA-05: surface a destructive badge with the
  // count of critical findings next to "Findings" in the nav. This
  // pulls attention to the most-actionable item without forcing the
  // user to open the page. We use `critical` (not `open`) because
  // a resolved-but-still-critical row is a different UX problem; the
  // signal we want here is "do I have something blowing up right now".
  // The hook is gated on `!!user` inside, so logged-out renders skip
  // the request entirely.
  const { data: findingStats } = useFindingStats()
  const criticalCount = findingStats?.critical ?? 0
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  // v2.4.23 audit a11y-20 (WCAG SC 2.1.2 No Keyboard Trap): the
  // mobile drawer should close on Esc — keyboard users were
  // forced to click the dim overlay to dismiss it. The listener
  // is only attached when the drawer is open so it doesn't
  // intercept Esc anywhere else.
  useEffect(() => {
    if (!mobileOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileOpen(false)
    }
    document.addEventListener("keydown", onKey)
    return () => document.removeEventListener("keydown", onKey)
  }, [mobileOpen])

  const handleLogout = async () => {
    await logout()
    router.push("/login")
  }

  const initials = user?.full_name
    ?.split(" ")
    .map((n: string) => n[0])
    .join("")
    .toUpperCase() || "U"

  const isActive = (href: string) => {
    if (href === "/dashboard") return pathname === "/dashboard"
    return pathname.startsWith(href)
  }

  const navContent = (
    <div className="flex h-full flex-col">
      {/* Logo */}
      <div className={cn("flex h-16 items-center border-b px-4", collapsed && "justify-center px-2")}>
        <Link href="/dashboard" className="flex items-center gap-2">
          <Logo size={32} />
          {!collapsed && <span className="text-lg font-bold tracking-tight">NIS2</span>}
        </Link>
        {!collapsed && (
          <Button
            variant="ghost"
            size="icon"
            className="ml-auto hidden lg:flex h-8 w-8"
            onClick={() => setCollapsed(true)}
            aria-label={ta("collapseSidebar")}
          >
            <ChevronLeft className="h-4 w-4" aria-hidden="true" />
          </Button>
        )}
      </div>

      {/* Org switcher (audit B-DRA-02). The component renders its
          own border+padding wrapper when visible, and `null` for
          users with a single membership — single-tenant installs see
          no extra chrome. */}
      <OrgSwitcher collapsed={collapsed} />

      {/* v2.4.23 audit a11y-01 (WCAG SC 4.1.3 Status Messages):
          dedicated polite live-region announces critical-finding
          count updates to screen readers. Without this, the
          destructive pill that v2.4.17 added is purely visual —
          a screen-reader user has no way to know the count
          changed without re-tabbing through the nav. The region
          lives outside the visible nav so its updates don't
          interfere with the badge's rendering. */}
      <span role="status" aria-live="polite" className="sr-only">
        {criticalCount > 0
          ? t("nav.criticalCountAnnouncement", { count: criticalCount })
          : ""}
      </span>

      {/* Main navigation */}
      <div className="flex-1 overflow-y-auto py-4">
        <nav className="space-y-1 px-2" aria-label={t("nav.primary")}>
          {mainNavKeys.map((item) => {
            // v2.4.17 audit O-DRA-05: per-nav-item destructive badge
            // with a count. Currently only "findings" shows one
            // (critical findings count). The map is set up so adding
            // future badges (e.g. unreviewed audit-log entries) is a
            // one-liner.
            const badge =
              item.key === "findings" && criticalCount > 0
                ? criticalCount
                : null
            const active = isActive(item.href)
            return (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileOpen(false)}
              // v2.4.23 audit a11y a11y-19 (WCAG SC 2.4.4 Link
              // Purpose): aria-current marks the active nav item
              // for screen-readers. Visual users get the
              // bg-sidebar-accent treatment; SR users get the
              // semantic equivalent.
              aria-current={active ? "page" : undefined}
              className={cn(
                "relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                active
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground",
                collapsed && "justify-center px-2"
              )}
              aria-label={
                badge !== null
                  ? `${t(`nav.${item.key}`)} (${badge} ${t("nav.criticalBadgeAria")})`
                  : (collapsed ? t(`nav.${item.key}`) : undefined)
              }
            >
              <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
              {!collapsed && <span className="flex-1">{t(`nav.${item.key}`)}</span>}
              {badge !== null && (
                // Destructive pill. On the collapsed sidebar (icon
                // only), render as a tiny dot so it doesn't fight
                // the icon for space; on the expanded sidebar, show
                // the actual count. The accessible announcement of
                // the count comes from the aria-live region above
                // the nav + the aria-label on the Link itself, so
                // the pill is purely visual decoration here.
                <span
                  aria-hidden="true"
                  className={cn(
                    "rounded-full bg-destructive text-destructive-foreground font-semibold",
                    collapsed
                      ? "absolute top-1 right-1 h-2 w-2"
                      : "ml-auto px-1.5 text-[10px] leading-5 min-w-[20px] text-center"
                  )}
                >
                  {!collapsed && (badge > 99 ? "99+" : badge)}
                </span>
              )}
            </Link>
          )})}
        </nav>

        <Separator className="my-4 mx-2" />

        <div className={cn("px-2", !collapsed && "px-4")}>
          {!collapsed && (
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {t('common.settings')}
            </p>
          )}
          <nav className="space-y-1" aria-label={t("nav.settings")}>
            {settingsNavKeys.map((item) => {
              const active = isActive(item.href)
              return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                aria-current={active ? "page" : undefined}
                aria-label={collapsed ? t(`nav.${item.key}`) : undefined}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  active
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground",
                  collapsed && "justify-center px-2"
                )}
              >
                <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                {!collapsed && <span>{t(`nav.${item.key}`)}</span>}
              </Link>
              )
            })}
          </nav>
        </div>
      </div>

      {/* User section */}
      <div className="border-t p-4">
        <div className={cn("flex items-center gap-3", collapsed && "justify-center")}>
          <Avatar className="h-8 w-8">
            <AvatarFallback className="text-xs">{initials}</AvatarFallback>
          </Avatar>
          {!collapsed && (
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{user?.full_name || "User"}</p>
              <p className="text-xs text-muted-foreground truncate">{user?.email || ""}</p>
            </div>
          )}
          {!collapsed && (
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0"
              onClick={handleLogout}
              aria-label={t("common.logout")}
            >
              <LogOut className="h-4 w-4" aria-hidden="true" />
            </Button>
          )}
        </div>
      </div>
    </div>
  )

  return (
    <>
      {/* Mobile trigger — v2.4.23 audit: icon-only button needs an
          accessible name + the visual state (open vs closed)
          surfaces via aria-expanded so screen-reader users know
          whether the next Tab takes them into the menu or past it. */}
      <Button
        variant="ghost"
        size="icon"
        className="fixed left-4 top-4 z-50 lg:hidden"
        onClick={() => setMobileOpen(!mobileOpen)}
        aria-label={mobileOpen ? ta("closeNavigation") : ta("openNavigation")}
        aria-expanded={mobileOpen}
        aria-controls="mobile-sidebar"
      >
        {mobileOpen ? <X className="h-5 w-5" aria-hidden="true" /> : <Menu className="h-5 w-5" aria-hidden="true" />}
      </Button>

      {/* Mobile overlay — also closes on Esc (a11y-20) so keyboard
          users have a way out beyond clicking the dim layer. */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Mobile sidebar */}
      <aside
        id="mobile-sidebar"
        aria-label={t("nav.primary")}
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 transform border-r bg-sidebar transition-transform duration-200 lg:hidden",
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {navContent}
      </aside>

      {/* Desktop sidebar */}
      <aside
        aria-label={t("nav.primary")}
        className={cn(
          "hidden lg:flex lg:flex-col lg:border-r lg:bg-sidebar transition-all duration-200",
          collapsed ? "lg:w-16" : "lg:w-64"
        )}
      >
        {collapsed && (
          <Button
            variant="ghost"
            size="icon"
            aria-label={ta("expandSidebar")}
            className="absolute -right-3 top-20 z-10 h-6 w-6 rounded-full border bg-background shadow-sm"
            onClick={() => setCollapsed(false)}
          >
            <ChevronLeft className="h-3 w-3 rotate-180" aria-hidden="true" />
          </Button>
        )}
        {navContent}
      </aside>
    </>
  )
}
