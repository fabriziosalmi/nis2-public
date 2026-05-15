// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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
  LifeBuoy,
  BookOpen,
  ExternalLink,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { Logo } from "@/components/brand/logo"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { OrgSwitcher } from "@/components/layout/org-switcher"
import { useAuthStore } from "@/stores/auth-store"
import { useFindingStats } from "@/hooks/use-findings"
import { useEffect, useRef, useState } from "react"

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

const supportNavKeys = [
  { key: "documentation", href: "https://github.com/fabriziosalmi/nis2-public/wiki", icon: BookOpen, external: true },
  { key: "support", href: "mailto:fabrizio.salmi@gmail.com", icon: LifeBuoy, external: true },
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

  // v2.4.25 audit a11y (WCAG SC 2.4.3 Focus Order): the mobile
  // drawer is a modal slide-out — when it's open, keyboard focus
  // must stay inside it. The previous (v2.4.23) implementation
  // closed on Esc but didn't constrain Tab, so Tab from the last
  // nav link landed on whatever happened to be in the document
  // BEHIND the dim overlay (the page main content the drawer was
  // meant to obscure). That's a confusing state for SR / keyboard
  // users and conventionally a focus-trap bug.
  //
  // The refs:
  //   - asideRef: scope for the focus query when computing
  //     "first / last focusable" to wrap Tab around.
  //   - triggerRef: the hamburger button that opened the drawer;
  //     focus returns here when the drawer closes (so the user's
  //     keyboard position is restored predictably, per SC 2.4.3).
  const asideRef = useRef<HTMLElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)

  // v2.4.23 audit a11y-20 (WCAG SC 2.1.2 No Keyboard Trap): the
  // mobile drawer should close on Esc — keyboard users were
  // forced to click the dim overlay to dismiss it.
  // v2.4.25: extended to also implement a focus trap (SC 2.4.3)
  // and focus restore on close.
  useEffect(() => {
    if (!mobileOpen) return
    const aside = asideRef.current
    if (!aside) return

    // The selector mirrors the de-facto "tabbable" set used by
    // every focus-trap library — anchor with href, non-disabled
    // form controls, and explicit tabindex>=0. We exclude
    // tabindex="-1" because those are programmatically focusable
    // but should not appear in the Tab order.
    const FOCUSABLE_SELECTOR =
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

    // Move focus into the drawer on open so the next Tab keystroke
    // lands somewhere inside, not back on the body. Defer to the
    // next frame because the drawer's `translate-x-0` transition
    // hasn't started yet — focusing while the element is still
    // visually offscreen is fine, but some browsers refuse to
    // focus an element with `display: none` ancestors.
    const initial = aside.querySelector<HTMLElement>(FOCUSABLE_SELECTOR)
    initial?.focus()

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMobileOpen(false)
        return
      }
      if (e.key !== "Tab") return

      // Re-query on every Tab so dynamically added/removed nav
      // links (e.g. the destructive findings badge appearing on
      // count change) participate in the trap.
      const focusables = aside.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
      if (focusables.length === 0) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      const active = document.activeElement as HTMLElement | null

      // Wrap shift+tab from first → last, tab from last → first.
      // Outside this trap the browser's default Tab order applies.
      if (e.shiftKey && (active === first || !aside.contains(active))) {
        last.focus()
        e.preventDefault()
      } else if (!e.shiftKey && (active === last || !aside.contains(active))) {
        first.focus()
        e.preventDefault()
      }
    }
    document.addEventListener("keydown", onKey)
    return () => {
      document.removeEventListener("keydown", onKey)
      // Restore focus to the trigger so the keyboard user's
      // position in the page is predictable. Defer to a microtask
      // because React may unmount the trigger if the drawer-close
      // navigation also unmounted the layout — a `?.focus()` in
      // that case is a no-op rather than an error.
      triggerRef.current?.focus()
    }
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

        <Separator className="my-4 mx-2" />

        <div className={cn("px-2", !collapsed && "px-4")}>
          {!collapsed && (
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {t('common.support')}
            </p>
          )}
          <nav className="space-y-1" aria-label={t("nav.support")}>
            {supportNavKeys.map((item) => {
              return (
              <a
                key={item.href}
                href={item.href}
                target={item.external ? "_blank" : undefined}
                rel={item.external ? "noopener noreferrer" : undefined}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground",
                  collapsed && "justify-center px-2"
                )}
                title={collapsed ? t(`nav.${item.key}`, { defaultValue: item.key }) : undefined}
              >
                <item.icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                {!collapsed && <span className="flex-1">{t(`nav.${item.key}`, { defaultValue: item.key.charAt(0).toUpperCase() + item.key.slice(1) })}</span>}
                {!collapsed && item.external && <ExternalLink className="h-3 w-3 text-muted-foreground" aria-hidden="true" />}
              </a>
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
          whether the next Tab takes them into the menu or past it.
          v2.4.25: ref'd so we can restore focus here when the
          drawer closes (SC 2.4.3 Focus Order). */}
      <Button
        ref={triggerRef}
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

      {/* Mobile sidebar — v2.4.25 a11y: ref'd + role=dialog +
          aria-modal so AT recognise it as a modal panel and the
          focus-trap useEffect above can scope its query to the
          drawer's contents.
          `inert` when closed prevents the slid-offscreen drawer
          from polluting the Tab order (translateX moves the
          element visually but doesn't disable focus on its
          descendants — pre-2.4.25 a mobile keyboard user tabbing
          through the main content would suddenly be focused on
          links inside the offscreen drawer). */}
      <aside
        ref={asideRef}
        id="mobile-sidebar"
        role="dialog"
        aria-modal="true"
        aria-label={t("nav.primary")}
        // React 19 supports `inert` natively as a boolean prop —
        // pre-2.4.30 we passed an empty string via spread to bridge
        // React-18 typings, but that triggered a "Received an empty
        // string for a boolean attribute" console warning on every
        // dashboard load (caught in the v2.4.30 console audit).
        // Now that we're committed to React 19, the empty-string
        // workaround is unnecessary and the boolean prop reads
        // cleanly.
        inert={!mobileOpen}
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 transform border-r bg-sidebar transition-transform duration-200 lg:hidden",
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {navContent}
      </aside>

      {/* Desktop sidebar — `relative` on the aside is load-bearing.
          The collapse-state expand button below is `position: absolute
          -right-3 top-20`. Pre-2.4.30 the aside was static-positioned,
          so the absolute button hunted up the ancestor tree for the
          first positioned element — which was nothing inside the
          dashboard layout, so it landed on `<html>`. Combined with
          the dashboard layout's outer `overflow-hidden`, the button
          ended up clipped past the right edge of the viewport and
          sat there permanently invisible AND unclickable, with the
          only recovery being a page reload (which reset `collapsed`
          to false). External-review repro: "se si comprime la colonna
          di sx poi non si riesce più a riallargarla". `relative`
          anchors the button to the aside's right border so the -3
          (–12px) offset puts it visibly half-on, half-off the sidebar
          edge as intended. */}
      <aside
        aria-label={t("nav.primary")}
        className={cn(
          "relative hidden lg:flex lg:flex-col lg:border-r lg:bg-sidebar transition-all duration-200",
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
