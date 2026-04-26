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
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { useAuthStore } from "@/stores/auth-store"
import { useState } from "react"

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
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const handleLogout = () => {
    logout()
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
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary text-primary-foreground font-bold text-sm">
            N2
          </div>
          {!collapsed && <span className="text-lg font-bold tracking-tight">NIS2</span>}
        </Link>
        {!collapsed && (
          <Button
            variant="ghost"
            size="icon"
            className="ml-auto hidden lg:flex h-8 w-8"
            onClick={() => setCollapsed(true)}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
        )}
      </div>

      {/* Main navigation */}
      <div className="flex-1 overflow-y-auto py-4">
        <nav className="space-y-1 px-2">
          {mainNavKeys.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileOpen(false)}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive(item.href)
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground",
                collapsed && "justify-center px-2"
              )}
            >
              <item.icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span>{t(`nav.${item.key}`)}</span>}
            </Link>
          ))}
        </nav>

        <Separator className="my-4 mx-2" />

        <div className={cn("px-2", !collapsed && "px-4")}>
          {!collapsed && (
            <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {t('common.settings')}
            </p>
          )}
          <nav className="space-y-1">
            {settingsNavKeys.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  isActive(item.href)
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground",
                  collapsed && "justify-center px-2"
                )}
              >
                <item.icon className="h-4 w-4 shrink-0" />
                {!collapsed && <span>{t(`nav.${item.key}`)}</span>}
              </Link>
            ))}
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
            <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={handleLogout}>
              <LogOut className="h-4 w-4" />
            </Button>
          )}
        </div>
      </div>
    </div>
  )

  return (
    <>
      {/* Mobile trigger */}
      <Button
        variant="ghost"
        size="icon"
        className="fixed left-4 top-4 z-50 lg:hidden"
        onClick={() => setMobileOpen(!mobileOpen)}
      >
        {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
      </Button>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={() => setMobileOpen(false)} />
      )}

      {/* Mobile sidebar */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 transform border-r bg-sidebar transition-transform duration-200 lg:hidden",
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {navContent}
      </aside>

      {/* Desktop sidebar */}
      <aside
        className={cn(
          "hidden lg:flex lg:flex-col lg:border-r lg:bg-sidebar transition-all duration-200",
          collapsed ? "lg:w-16" : "lg:w-64"
        )}
      >
        {collapsed && (
          <Button
            variant="ghost"
            size="icon"
            className="absolute -right-3 top-20 z-10 h-6 w-6 rounded-full border bg-background shadow-sm"
            onClick={() => setCollapsed(false)}
          >
            <ChevronLeft className="h-3 w-3 rotate-180" />
          </Button>
        )}
        {navContent}
      </aside>
    </>
  )
}
