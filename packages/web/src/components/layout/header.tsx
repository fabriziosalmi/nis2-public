// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useTranslations } from "next-intl"

import { usePathname, useRouter } from "next/navigation"
import { User, Settings, LogOut, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { useAuthStore } from "@/stores/auth-store"
import { LanguageSwitcher } from "@/components/layout/language-switcher"
import { ThemeToggle } from "@/components/layout/theme-toggle"
import Link from "next/link"

function getBreadcrumbs(pathname: string) {
  const segments = pathname.split("/").filter(Boolean)
  const crumbs: { label: string; href: string }[] = []

  let path = ""
  for (const segment of segments) {
    path += `/${segment}`
    const label = segment.charAt(0).toUpperCase() + segment.slice(1).replace(/-/g, " ")
    crumbs.push({ label, href: path })
  }

  return crumbs
}

export function Header() {
  const pathname = usePathname()
  const router = useRouter()
  const { user, logout } = useAuthStore()
  const t = useTranslations()
  // v2.4.23 audit a11y namespace for accessibility-only strings
  // (breadcrumb landmark label, user-menu trigger label).
  const ta = useTranslations("a11y")
  const breadcrumbs = getBreadcrumbs(pathname)

  // Avatar fallback: prefer initials from full_name, fall back to the
  // first letter of the email (always present for an authed user), and
  // only fall back to a generic "U" if neither is available — which in
  // practice would only happen during the brief window before
  // /auth/me hydrates. v2.4.15 audit nit (N-DRA-01).
  const initials =
    user?.full_name
      ?.split(" ")
      .map((n: string) => n[0])
      .join("")
      .toUpperCase() ||
    user?.email?.[0]?.toUpperCase() ||
    "U"

  const handleLogout = async () => {
    await logout()
    router.push("/login")
  }

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 px-6 pl-14 lg:pl-6">
      {/* Breadcrumbs — v2.4.23 audit a11y-19 (WCAG SC 2.4.8 Location):
          a screen-reader user landing on /dashboard/findings/abc123
          had no programmatic signal that this was breadcrumb
          navigation, nor which crumb represented the current page.
          The fixes:
            1. aria-label on <nav> identifies the landmark as
               "Breadcrumb" so AT users can jump to it directly.
            2. <ol> + <li> gives the crumbs a positional semantics
               ("3 of 4") that matches the visual chevron chain.
            3. aria-current="page" on the trailing crumb tells the
               SR which one is the active page (the visual cue is
               just font-weight, which AT can't see).
            4. aria-hidden on the decorative chevron separators —
               otherwise SR users hear "right-pointing chevron"
               between every crumb. */}
      <nav aria-label={ta("breadcrumb")} className="flex items-center gap-1 text-sm text-muted-foreground min-w-0">
        <ol className="flex items-center gap-1">
          {breadcrumbs.map((crumb, i) => {
            const isLast = i === breadcrumbs.length - 1
            return (
              <li key={crumb.href} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="h-3 w-3" aria-hidden="true" />}
                {isLast ? (
                  <span className="font-medium text-foreground" aria-current="page">
                    {crumb.label}
                  </span>
                ) : (
                  <Link href={crumb.href} className="hover:text-foreground transition-colors">
                    {crumb.label}
                  </Link>
                )}
              </li>
            )
          })}
        </ol>
      </nav>

      <div className="ml-auto flex items-center gap-2">
        {/* The header used to render a search button styled as an input
            with a Ctrl+K kbd hint, but no command palette ever shipped
            behind it — the `<Button>` had no onClick, no handler, no
            destination. v2.4.15 removes the dead UX (audit B-DRA-01).
            A real cmdk command palette is on the roadmap for v2.4.16+
            and the `header.searchPlaceholder` i18n key is intentionally
            kept in messages/*.json so it's ready to wire up. */}

        {/* Theme + language switchers */}
        <ThemeToggle />
        <LanguageSwitcher />

        {/* User menu — v2.4.23 audit a11y-15 (WCAG SC 4.1.2): the
            trigger is an avatar with no visible text, so without an
            aria-label SR users heard "button" with no idea what
            activating it would do. Surfacing the user's name in the
            label both names the button and gives context about
            *whose* menu opens. */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              className="relative h-8 w-8 rounded-full"
              aria-label={ta("userMenu", { name: user?.full_name || user?.email || "User" })}
            >
              <Avatar className="h-8 w-8">
                <AvatarFallback className="text-xs">{initials}</AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-56" align="end" forceMount>
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col space-y-1">
                <p className="text-sm font-medium leading-none">{user?.full_name || "User"}</p>
                <p className="text-xs leading-none text-muted-foreground">{user?.email || ""}</p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => router.push("/dashboard/settings/profile")}>
              <User className="mr-2 h-4 w-4" aria-hidden="true" />
              <span>{t('nav.profile')}</span>
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => router.push("/dashboard/settings")}>
              <Settings className="mr-2 h-4 w-4" aria-hidden="true" />
              <span>{t('common.settings')}</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout}>
              <LogOut className="mr-2 h-4 w-4" aria-hidden="true" />
              <span>{t('common.logout')}</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
