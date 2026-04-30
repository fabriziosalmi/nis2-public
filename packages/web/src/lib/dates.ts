// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.4.17 audit S-DRA-01: locale-aware date formatting.
//
// Pre-v2.4.17, every page that rendered a date called `format(new
// Date(...), "MMM d, yyyy")` from `date-fns` directly. That ignored
// the user's selected app locale: a user with the UI in Italian or
// French still saw "Apr 28, 2026" because date-fns falls back to its
// internal English-US locale when none is passed.
//
// This helper bridges the next-intl `useLocale()` hook to date-fns'
// `Locale` objects. Every date render in the dashboard now goes
// through `useFormatDate()`, which closes the loop.
//
// We import only the 5 locales the UI ships (en/it/fr/de/es) so the
// production bundle doesn't ship 60+ unused locale chunks.

import { format } from "date-fns"
import { enUS as enUSLocale } from "date-fns/locale/en-US"
import { it as itLocale } from "date-fns/locale/it"
import { fr as frLocale } from "date-fns/locale/fr"
import { de as deLocale } from "date-fns/locale/de"
import { es as esLocale } from "date-fns/locale/es"
import type { Locale } from "date-fns"
import { useLocale } from "next-intl"

const LOCALE_MAP: Record<string, Locale> = {
  en: enUSLocale,
  "en-US": enUSLocale,
  it: itLocale,
  fr: frLocale,
  de: deLocale,
  es: esLocale,
}

/**
 * React hook returning a date-formatting function bound to the
 * user's active locale. Use it instead of importing `format` from
 * `date-fns` directly.
 *
 * Usage:
 *   const formatDate = useFormatDate()
 *   <span>{formatDate(scan.created_at, "PP")}</span>
 *
 * Accepts the same format string as `date-fns` `format()`. We
 * recommend the localised tokens (`PP`, `Pp`, `PPP`, `PPPP`) over
 * literal patterns (`MMM d, yyyy`) so the user gets natural ordering
 * for their language ("28 apr 2026" in IT vs "Apr 28, 2026" in EN).
 *
 * Returns "—" for `null` / `undefined` / falsy timestamps so the
 * caller doesn't need to guard.
 */
export function useFormatDate() {
  const locale = useLocale()
  const dateLocale = LOCALE_MAP[locale] ?? enUSLocale

  return (value: string | Date | null | undefined, pattern = "PP"): string => {
    if (!value) return "—"
    const d = typeof value === "string" ? new Date(value) : value
    if (isNaN(d.getTime())) return "—"
    return format(d, pattern, { locale: dateLocale })
  }
}
