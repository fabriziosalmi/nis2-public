// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import type { Metadata } from "next"
import { Manrope, JetBrains_Mono } from "next/font/google"
import "./globals.css"
import { Providers } from "@/components/layout/providers"
import { NextIntlClientProvider } from "next-intl"
import { getLocale, getMessages } from "next-intl/server"
import { headers } from "next/headers"

const sansFont = Manrope({ subsets: ["latin"], variable: "--font-sans" })
const monoFont = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" })

export const metadata: Metadata = {
  title: "NIS2 Platform",
  description: "NIS2 Compliance Scanning and Monitoring Platform",
  // Same SVG mark as the docs site / sidebar / login screen — keeps
  // browser tabs, bookmarks, and home-screen icons visually consistent
  // with the in-app branding.
  icons: {
    icon: [{ url: "/favicon.svg", type: "image/svg+xml" }],
    apple: "/logo.svg",
  },
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = await getLocale()
  const messages = await getMessages()
  // CSP nonce minted per-request in middleware.ts — hand it to next-themes so
  // its pre-hydration inline theme script carries the nonce. Without it the
  // strict prod CSP blocks that one script: a flash of the wrong theme + a
  // console CSP error (every other inline script is nonced by Next itself).
  const nonce = (await headers()).get("x-nonce") ?? undefined

  return (
    // suppressHydrationWarning on <html> covers next-themes' class swap.
    // The same flag on <body> covers attributes injected by browser
    // extensions (ColorZilla's `cz-shortcut-listen`, Grammarly's
    // `data-gr-*`, dark-reader, etc.) before React hydrates. These are
    // outside our control and produce noisy dev warnings that mask real
    // mismatches; suppressing them here only silences the *attribute*
    // diff on this element, not deeper-tree hydration bugs.
    <html lang={locale} suppressHydrationWarning>
      <body
        className={`${sansFont.variable} ${monoFont.variable} font-sans antialiased tabular-nums`}
        suppressHydrationWarning
      >
        <NextIntlClientProvider messages={messages}>
          <Providers nonce={nonce}>{children}</Providers>
        </NextIntlClientProvider>
      </body>
    </html>
  )
}
