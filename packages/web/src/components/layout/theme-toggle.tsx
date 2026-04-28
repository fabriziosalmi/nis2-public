// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect, useState } from "react"
import { useTheme } from "next-themes"
import { Monitor, Moon, Sun } from "lucide-react"
import { useTranslations } from "next-intl"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

/**
 * Light / Dark / System theme switcher.
 *
 * Why a tri-state and not a two-state toggle: macOS / Windows respect a
 * user-level dark/light preference and we want "follow OS" to be a
 * first-class option, not something the user has to unset by toggling
 * twice. The `system` choice persists in localStorage via next-themes.
 *
 * The component renders nothing pre-mount: next-themes doesn't know the
 * resolved theme until after hydration, and rendering the wrong icon for
 * a frame trips a hydration warning. Returning a fixed-size placeholder
 * keeps layout stable.
 */
export function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme()
  const t = useTranslations("header")
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  // Reserve the slot during SSR / first paint so the header doesn't shift
  // when the icon resolves.
  if (!mounted) {
    return <Button variant="ghost" size="icon" aria-hidden="true" className="opacity-0" />
  }

  // Show the icon for the *currently rendered* theme, not the user's
  // preference. If the user picked "system" and the OS is dark, we want
  // the moon — the dropdown still highlights "system" as the active row.
  const Icon = resolvedTheme === "dark" ? Moon : Sun

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Theme">
          <Icon className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem
          onClick={() => setTheme("light")}
          className={theme === "light" ? "bg-accent" : undefined}
        >
          <Sun className="mr-2 h-4 w-4" />
          {t("lightMode")}
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("dark")}
          className={theme === "dark" ? "bg-accent" : undefined}
        >
          <Moon className="mr-2 h-4 w-4" />
          {t("darkMode")}
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("system")}
          className={theme === "system" ? "bg-accent" : undefined}
        >
          <Monitor className="mr-2 h-4 w-4" />
          {t("systemMode")}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
