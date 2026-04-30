// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.5.2 — Legal-disclaimer interstitial.
//
// Pattern: consent-before-interaction. Pre-2.5.2 a visitor landing on
// `/` saw the marketing surface, the compliance score, the demo
// references, and the operator information all at once — and a
// downstream legal claim of "the platform told me I was compliant"
// would have nothing in the audit trail to cite as a deliberate
// disclaimer event. This modal closes that gap:
//
//   1. First-time visitors get a blocking dialog stating the platform
//      provides automated classifications on a SUBSET of NIS2, NOT
//      legal advice. They must click "Ho compreso — Procedi" to
//      proceed.
//   2. Acceptance is persisted in localStorage under a versioned key
//      (`STORAGE_KEY` below). Bumping the version forces every visitor
//      to re-acknowledge — useful when terms or privacy notice change
//      materially.
//   3. The two key references (Terms + Privacy) are rendered as
//      explicit links INSIDE the modal so the visitor cannot deny
//      having seen them.
//   4. Suppressed for authenticated users — they accepted at register
//      time and re-acknowledging on every dashboard visit would be
//      noise. The check is gated on `useAuthHydrated()` so we don't
//      flash the modal during auth-store rehydration on a logged-in
//      session.
//
// Coordination with the dashboard app and the docs site:
//   - This component handles ONLY the unauthenticated public landing
//     at `/`. The dashboard layout requires login, which itself
//     constitutes acceptance of Terms (per docs/terms.md §2 and the
//     register form).
//   - The docs site at `fabriziosalmi.github.io/nis2-public/` ships
//     a separate Vue port of this modal in `theme/components/Home.vue`
//     (different origin → distinct localStorage; same UX).
"use client"

import { useEffect, useState } from "react"
import { ShieldCheck } from "lucide-react"
import { useTranslations } from "next-intl"
import { Button } from "@/components/ui/button"
import { useAuthStore, useAuthHydrated } from "@/stores/auth-store"

// Versioned storage key. If the substantive content of the disclaimer
// changes (terms revision, new processing purpose, scope expansion),
// bump the suffix to force every previous "accepted" decision to
// expire. Acceptance with a stale key has no legal value.
const STORAGE_KEY = "nis2-legal-disclaimer-v1"

const TERMS_URL = "https://github.com/fabriziosalmi/nis2-public/blob/main/docs/terms.md"
const PRIVACY_URL = "https://github.com/fabriziosalmi/nis2-public/blob/main/docs/privacy.md"

export function LegalDisclaimerModal() {
  const t = useTranslations("landingPage.legalDisclaimer")
  const hydrated = useAuthHydrated()
  const user = useAuthStore((s) => s.user)
  const [show, setShow] = useState(false)
  // v2.5.3: gate the entire render behind a post-mount flag so the
  // server-rendered HTML for this component is *always* an empty
  // tree. Reported by an external reviewer as a Next 15 hydration
  // error ("server rendered text didn't match the client") on a
  // fresh clone — even though the previous logic only flipped `show`
  // inside a useEffect, the modal's children include `useTranslations`
  // calls and lucide icons that strict modes can flag as differing
  // between SSR and client. The cheapest robust fix is to render
  // nothing at all on the server — the visitor sees the dialog ~50ms
  // after first paint, which is the same UX trade-off documented in
  // v2.5.2 anyway.
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    if (!mounted) return
    // Wait for auth-store rehydration before deciding — otherwise a
    // returning logged-in visitor would see a flash of the modal on
    // every page load while Zustand still thinks they're anonymous.
    if (!hydrated) return
    // Authenticated users implicitly accepted at register. The
    // dashboard pages enforce auth and the dashboard footer keeps
    // the Terms / Privacy links reachable.
    if (user) return
    try {
      if (localStorage.getItem(STORAGE_KEY) !== "accepted") {
        setShow(true)
      }
    } catch {
      // Private browsing / disabled localStorage: show the modal once
      // per session as the safer default.
      setShow(true)
    }
  }, [mounted, hydrated, user])

  // While the modal is open, prevent body scroll so the user's
  // attention stays on the consent dialog. Restored on close.
  useEffect(() => {
    if (!show) return
    const prev = document.body.style.overflow
    document.body.style.overflow = "hidden"
    return () => {
      document.body.style.overflow = prev
    }
  }, [show])

  // SSR + first-mount renders nothing — see comment on the `mounted`
  // state above for the reasoning.
  if (!mounted) return null
  if (!show) return null

  const accept = () => {
    try {
      localStorage.setItem(STORAGE_KEY, "accepted")
    } catch {
      /* no persistence — user will see the dialog on next visit */
    }
    setShow(false)
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="legal-disclaimer-title"
      aria-describedby="legal-disclaimer-body"
      className="fixed inset-0 z-[100] flex items-center justify-center bg-slate-950/95 p-4 backdrop-blur-sm"
    >
      <div className="w-full max-w-xl rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl sm:p-10">
        <ShieldCheck
          className="mx-auto mb-6 h-10 w-10 text-slate-400"
          aria-hidden="true"
          strokeWidth={1.75}
        />
        <h2
          id="legal-disclaimer-title"
          className="text-center text-2xl font-bold tracking-tight text-slate-100"
        >
          {t("title")}
        </h2>
        <p
          id="legal-disclaimer-body"
          className="mt-6 text-center text-base leading-relaxed text-slate-300"
        >
          {t("body")}
        </p>
        <div className="mt-6 flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-sm">
          <a
            href={TERMS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-blue-400 underline-offset-4 hover:underline"
          >
            {t("terms")}
          </a>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <a
            href={PRIVACY_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-blue-400 underline-offset-4 hover:underline"
          >
            {t("privacy")}
          </a>
        </div>
        <Button
          onClick={accept}
          size="lg"
          className="mt-8 w-full !bg-blue-600 !text-white hover:!bg-blue-500"
        >
          {t("accept")}
        </Button>
      </div>
    </div>
  )
}
