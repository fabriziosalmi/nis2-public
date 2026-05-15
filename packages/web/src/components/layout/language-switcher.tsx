// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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

// Source-of-truth for the dropdown contents. Pre-2.4.27 this list
// included `pt` even though `messages/pt.json` does not exist —
// `i18n.ts` correctly excludes pt from the negotiation set, so a user
// who picked "Português" wrote a cookie that was then silently
// rejected and the UI snapped back to English on the next render.
// Listing only the locales we actually ship keeps the switcher and
// the negotiator in lockstep; add an entry here only when the
// matching JSON file ships.
const locales = [
  { code: "en" },
  { code: "it" },
  { code: "fr" },
  { code: "de" },
  { code: "es" },
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
            <span aria-hidden="true" className="font-mono text-[10px] text-muted-foreground w-4">{locale.code.toUpperCase()}</span>
            <span className="font-medium">{t(locale.code)}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
