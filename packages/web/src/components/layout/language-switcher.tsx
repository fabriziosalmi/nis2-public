// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useLocale, useTranslations } from "next-intl"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Languages } from "lucide-react"

const locales = [
  { code: "en", flag: "🇬🇧" },
  { code: "it", flag: "🇮🇹" },
  { code: "fr", flag: "🇫🇷" },
  { code: "de", flag: "🇩🇪" },
  { code: "es", flag: "🇪🇸" },
  { code: "pt", flag: "🇵🇹" },
] as const

export function LanguageSwitcher() {
  const t = useTranslations("language")
  const ta = useTranslations("a11y")
  const currentLocale = useLocale()
  const router = useRouter()

  const setLocale = (locale: string) => {
    document.cookie = `locale=${locale};path=/;max-age=31536000;SameSite=Lax`
    router.refresh()
  }

  // v2.4.23 audit a11y-02 (WCAG SC 4.1.2): the previous label was
  // "Switch language" verbatim in English even when the rest of the
  // UI was Italian / French / etc. Now localised via the `a11y`
  // namespace; also surfaces the CURRENT locale name so screen-
  // reader users know what's active before they pop the dropdown.
  const currentLocaleName = (() => {
    try {
      return t(currentLocale as any)
    } catch {
      return currentLocale
    }
  })()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9"
          aria-label={ta("languageSwitcher", { current: currentLocaleName })}
        >
          <Languages className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {locales.map((locale) => (
          <DropdownMenuItem
            key={locale.code}
            onClick={() => setLocale(locale.code)}
            className="cursor-pointer gap-2"
            aria-current={locale.code === currentLocale ? "true" : undefined}
          >
            <span aria-hidden="true">{locale.flag}</span>
            <span>{t(locale.code)}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
