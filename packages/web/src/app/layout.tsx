// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"
import { Providers } from "@/components/layout/providers"
import { NextIntlClientProvider } from "next-intl"
import { getLocale, getMessages } from "next-intl/server"

const inter = Inter({ subsets: ["latin"], variable: "--font-sans" })

export const metadata: Metadata = {
  title: "NIS2 Platform",
  description: "NIS2 Compliance Scanning and Monitoring Platform",
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const locale = await getLocale()
  const messages = await getMessages()

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
        className={`${inter.variable} font-sans antialiased`}
        suppressHydrationWarning
      >
        <NextIntlClientProvider messages={messages}>
          <Providers>{children}</Providers>
        </NextIntlClientProvider>
      </body>
    </html>
  )
}
