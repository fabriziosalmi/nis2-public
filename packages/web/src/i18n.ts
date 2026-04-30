// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { getRequestConfig } from 'next-intl/server'
import { cookies, headers } from 'next/headers'

// Note: `pt` is declared as a supported locale, but we don't ship a
// pt.json yet. Until v2.4.12 lands the file we keep `pt` out of the
// negotiation set so a Portuguese browser doesn't get a 500 on first
// paint trying to import a non-existent JSON.
export const locales = ['en', 'it', 'fr', 'de', 'es'] as const
export type Locale = (typeof locales)[number]
export const defaultLocale: Locale = 'en'

/**
 * Parse `Accept-Language` and pick the best supported locale.
 *
 * RFC 7231 syntax: `en-US,en;q=0.9,it;q=0.8`. We split on commas, peel
 * off the q-value, sort by priority, and walk the list looking for a
 * direct match (`it`) or a prefix match (`it-IT` → `it`). Falls through
 * to `defaultLocale` if none matches.
 *
 * Why this matters: previously the app always rendered English on first
 * visit unless the user manually flipped the language switcher (which
 * sets the cookie). An Italian user landing on /login from an Italian-
 * configured browser saw an English form. Reported by Davide
 */
function negotiateAcceptLanguage(header: string | null): Locale | null {
  if (!header) return null
  const items = header
    .split(',')
    .map((raw) => {
      const [tag, ...params] = raw.trim().split(';')
      const qParam = params.find((p) => p.trim().startsWith('q='))
      const q = qParam ? Number(qParam.split('=')[1]) : 1
      return { tag: tag.toLowerCase(), q: Number.isFinite(q) ? q : 0 }
    })
    .sort((a, b) => b.q - a.q)
  for (const { tag } of items) {
    if ((locales as readonly string[]).includes(tag)) return tag as Locale
    const prefix = tag.split('-')[0]
    if ((locales as readonly string[]).includes(prefix)) return prefix as Locale
  }
  return null
}

export default getRequestConfig(async () => {
  const cookieStore = await cookies()
  const fromCookie = cookieStore.get('locale')?.value as Locale | undefined

  // Cookie wins (explicit user choice via the language switcher). When
  // missing, fall back to the browser's Accept-Language. Last resort:
  // defaultLocale.
  let locale: Locale = defaultLocale
  if (fromCookie && (locales as readonly string[]).includes(fromCookie)) {
    locale = fromCookie
  } else {
    const hdrs = await headers()
    const negotiated = negotiateAcceptLanguage(hdrs.get('accept-language'))
    if (negotiated) locale = negotiated
  }

  return {
    locale,
    messages: (await import(`../messages/${locale}.json`)).default,
  }
})
