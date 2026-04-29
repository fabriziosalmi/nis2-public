// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect } from "react"

/**
 * v2.4.24 audit a11y-11 (WCAG SC 2.4.2 Page Titled): every web page
 * needs a unique, descriptive `<title>` so screen-reader users hear
 * where they are when a page loads, browser tabs are distinguishable
 * at a glance, and bookmarks / browser history aren't all stamped
 * with the same generic "NIS2 Platform" string.
 *
 * The App Router exposes per-route metadata only from server
 * components (`export const metadata` / `generateMetadata`). The
 * dashboard pages are all client components ("use client") because
 * they pull from TanStack Query / Zustand stores that need browser-
 * only APIs. Splitting each route into a server-component shell +
 * client-component body is a 22-route refactor; instead this hook
 * mutates `document.title` directly in a useEffect, which is the
 * idiomatic React-in-the-App-Router pattern for this case.
 *
 * The previous `<title>` is restored on unmount so navigating back
 * to a page without the hook (or to the implicit "NIS2 Platform"
 * default from the root layout) doesn't leave the previous page's
 * title stuck in the tab.
 *
 * @param title  page-specific portion of the title — already
 *               localised by the caller via `useTranslations`
 */
export function useDocumentTitle(title: string) {
  useEffect(() => {
    if (!title) return
    const previous = document.title
    document.title = `${title} — NIS2 Platform`
    return () => {
      document.title = previous
    }
  }, [title])
}
