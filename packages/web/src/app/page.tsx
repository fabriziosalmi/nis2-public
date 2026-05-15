// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.4.27 — public landing page.
//
// Pre-2.4.27 the index route was a 19-line redirect to /login or
// /dashboard, with a "Loading…" spinner during hydration. That worked
// for users who already knew what the platform was — and was a dead end
// for everyone arriving from a search result, a backlink, or a board
// member's email.
//
// v2.4.27a — i18n.
//
// The first cut of this file was English-only "by design" because the
// dashboard alone ships ~1.2k translated keys and adding ~80 more for
// a marketing surface felt like scope creep. It wasn't — an Italian
// CISO landing on the front door from a `consulenza nis2` search and
// reading English copy is a worse first impression than an under-
// translated dashboard. So we wired this through next-intl on the
// `landingPage` namespace; every visible string now resolves through
// `t()` against en/it/fr/de/es.
//
// What stays hardcoded:
//   - Proper nouns and legal references that aren't translated in
//     practice: "NIS2", "Art. 21", "MCP", "AGPL-3.0", "PostgreSQL",
//     CLI snippets like `make dev`, the company name "Fabrizio Salmi".
//   - Number-only stats (30+, 5, 0) — translated locale text wraps
//     around them via the namespace.
"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { useTranslations } from "next-intl"
import {
  ShieldCheck,
  Radar,
  AlertCircle,
  Building2,
  Activity,
  Bot,
  ArrowRight,
  Github,
  Lock,
  Server,
  Code2,
  Check,
  Globe,
  Terminal,
  Menu,
  X,
} from "lucide-react"
import { Logo } from "@/components/brand/logo"
import { Button } from "@/components/ui/button"
import { StaggerContainer, StaggerItem } from "@/components/ui/fade-in"
import { LegalDisclaimerModal } from "@/components/legal/legal-disclaimer-modal"
import { useAuthStore, useAuthHydrated } from "@/stores/auth-store"
import { cn } from "@/lib/utils"

// Tech-stack pills for the trust strip — kept hardcoded because every
// item is a product name that doesn't get translated.
const STACK = [
  "Next.js 15",
  "React 19",
  "FastAPI",
  "PostgreSQL 16",
  "Celery",
  "Tailwind v4",
  "MCP",
] as const

// Each feature card maps to one router family in the API surface so
// the marketing line traces back to actual code; the i18n key segment
// matches the README anchor for searchability.
const FEATURES = [
  { key: "governance", icon: ShieldCheck, href: "https://github.com/fabriziosalmi/nis2-public#nis2-directive-coverage", label: "Art. 21" },
  { key: "validation", icon: Radar, href: "https://github.com/fabriziosalmi/nis2-public#technical-validation-engine-30-checks", label: "Scanner" },
  { key: "incident", icon: AlertCircle, href: "https://github.com/fabriziosalmi/nis2-public#art-23--incident-reporting-csirt", label: "Art. 23" },
  { key: "supply", icon: Building2, href: "https://github.com/fabriziosalmi/nis2-public#art-18--supply-chain-vendor-risk-management", label: "Art. 18" },
  { key: "bia", icon: Activity, href: "https://github.com/fabriziosalmi/nis2-public#business-impact-analysis-bia", label: "BIA" },
  { key: "ai", icon: Bot, href: "https://github.com/fabriziosalmi/nis2-public#tech-stack", label: "MCP" },
] as const

const STEPS = ["step1", "step2", "step3"] as const
const AUDIENCES = ["ciso", "dpo", "consultant", "secops"] as const

export default function Home() {
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const hydrated = useAuthHydrated()

  // Preserve the pre-2.4.27 redirect for authenticated users — power
  // users with a session typing the bare domain still land on
  // /dashboard. Unauthenticated visitors see this landing page; that
  // is the entire delta.
  useEffect(() => {
    if (!hydrated) return
    if (user) router.replace("/dashboard")
  }, [hydrated, user, router])

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Legal-disclaimer interstitial. Renders nothing when the
          visitor has already acknowledged (localStorage) or is
          authenticated. Mounted at the top so the dialog backdrop
          covers the entire landing during first visit. */}
      <LegalDisclaimerModal />
      <SiteHeader />
      <main>
        <Hero />
        <TrustStrip />
        <FeatureGrid />
        <Showcase />
        <HowItWorks />
        <Audiences />
        <SelfHosted />
        <FinalCta />
      </main>
      <SiteFooter />
    </div>
  )
}

function SiteHeader() {
  const t = useTranslations("landingPage.header")
  const [mobileOpen, setMobileOpen] = useState(false)

  // Prevent scroll when mobile menu is open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = "hidden"
    } else {
      document.body.style.overflow = "unset"
    }
    return () => { document.body.style.overflow = "unset" }
  }, [mobileOpen])

  return (
    <>
      <header className="sticky top-0 z-30 w-full border-b bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
          <Link href="/" className="flex items-center gap-2.5" aria-label={t("homeAria")}>
            <Logo size={28} />
            <span className="font-semibold tracking-tight">NIS2 Platform</span>
            <span className="hidden text-xs font-medium text-muted-foreground sm:inline">
              · {t("tagline")}
            </span>
          </Link>
          <nav className="flex items-center gap-2" aria-label={t("primaryNav")}>
            <div className="hidden md:flex items-center gap-1">
              <Button asChild variant="ghost" size="sm">
                <a
                  href="https://github.com/fabriziosalmi/nis2-public#readme"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {t("docs")}
                </a>
              </Button>
              <Button asChild variant="ghost" size="sm">
                <a
                  href="https://github.com/fabriziosalmi/nis2-public"
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={t("githubAria")}
                >
                  <Github className="h-4 w-4" aria-hidden="true" />
                  {t("github")}
                </a>
              </Button>
            </div>
            
            <div className="hidden sm:flex items-center gap-1">
              <Button asChild variant="ghost" size="sm">
                <Link href="/login">{t("signIn")}</Link>
              </Button>
              <Button asChild size="sm">
                <Link href="/register">
                  {t("getStarted")}
                  <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
                </Link>
              </Button>
            </div>

            <Button
              variant="ghost"
              size="icon"
              className="md:hidden"
              onClick={() => setMobileOpen(true)}
              aria-label="Open mobile menu"
            >
              <Menu className="h-5 w-5" />
            </Button>
          </nav>
        </div>
      </header>

      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <div className="fixed inset-0 bg-background/80 backdrop-blur-sm" onClick={() => setMobileOpen(false)} aria-hidden="true" />
          <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xs border-l bg-background p-6 shadow-lg sm:max-w-sm">
            <div className="flex items-center justify-between mb-8">
              <span className="font-semibold tracking-tight">NIS2 Platform</span>
              <Button variant="ghost" size="icon" onClick={() => setMobileOpen(false)}>
                <X className="h-5 w-5" />
              </Button>
            </div>
            
            <div className="flex flex-col gap-6">
              <div className="flex flex-col gap-3">
                <p className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">Navigazione</p>
                <a
                  href="https://github.com/fabriziosalmi/nis2-public#readme"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm font-medium p-2 hover:bg-muted rounded-md transition-colors"
                >
                  {t("docs")}
                </a>
                <a
                  href="https://github.com/fabriziosalmi/nis2-public"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm font-medium p-2 hover:bg-muted rounded-md transition-colors"
                >
                  <Github className="h-4 w-4" />
                  {t("github")}
                </a>
              </div>
              <div className="flex flex-col gap-3 pt-6 border-t">
                <Button asChild variant="outline" className="w-full justify-center">
                  <Link href="/login" onClick={() => setMobileOpen(false)}>{t("signIn")}</Link>
                </Button>
                <Button asChild className="w-full justify-center">
                  <Link href="/register" onClick={() => setMobileOpen(false)}>
                    {t("getStarted")}
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function Hero() {
  const t = useTranslations("landingPage.hero")
  // The "Already have an account? Sign in" link reuses the
  // header.signIn key so we don't ship two near-identical translations
  // for the same word.
  const th = useTranslations("landingPage.header")
  return (
    <section className="relative overflow-hidden">
      {/* Decorative gradient — purely visual. aria-hidden so SR users
          don't waste a focus on a meaningless blob. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(60%_50%_at_50%_-10%,rgba(59,130,246,0.15),transparent_60%),radial-gradient(40%_40%_at_80%_30%,rgba(110,64,201,0.10),transparent_70%)]"
      />
      <div className="mx-auto max-w-7xl px-4 pb-16 pt-20 sm:px-6 sm:pt-24 lg:px-8 lg:pt-32">
        <div className="mx-auto max-w-3xl text-center">
          <div
            className="mx-auto inline-flex items-center gap-2 rounded-full border bg-card/80 px-3 py-1 text-xs font-medium text-muted-foreground shadow-sm"
            aria-label={t("metaAria")}
          >
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" aria-hidden="true" />
            {t("badge")}
          </div>
          <h1 className="mt-6 text-balance text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
            {t("headlineStart")}{" "}
            <span className="bg-gradient-to-br from-blue-600 to-violet-600 bg-clip-text text-transparent">
              {t("headlineEnd")}
            </span>
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-pretty text-lg text-muted-foreground">
            {t("subtitle")}
          </p>
          <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Button asChild size="lg" className="w-full sm:w-auto">
              <Link href="/register">
                {t("ctaPrimary")}
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline" className="w-full sm:w-auto">
              <a
                href="https://github.com/fabriziosalmi/nis2-public"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Github className="h-4 w-4" aria-hidden="true" />
                {t("ctaSecondary")}
              </a>
            </Button>
          </div>
          <p className="mt-4 text-xs text-muted-foreground">
            {t("alreadyAccount")}{" "}
            <Link href="/login" className="font-medium text-foreground underline-offset-4 hover:underline">
              {th("signIn")}
            </Link>
          </p>
        </div>
      </div>
    </section>
  )
}

function TrustStrip() {
  const t = useTranslations("landingPage.trust")
  // Numeric values stay hardcoded; only the labels translate. Order of
  // (value, label) keeps the visual grid stable across languages.
  const stats: ReadonlyArray<{ v: string; k: string }> = [
    { v: "30+", k: t("checks") },
    { v: "5", k: t("languages") },
    { v: t("coverageValue"), k: t("coverage") },
    { v: "0", k: t("deps") },
  ]
  return (
    <section
      aria-label={t("ariaLabel")}
      className="border-y bg-muted/30"
    >
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <dl className="grid grid-cols-2 gap-6 sm:grid-cols-4 sm:gap-4">
          {stats.map((s) => (
            <div key={s.k} className="text-center">
              <dt className="text-xs uppercase tracking-wider text-muted-foreground">
                {s.k}
              </dt>
              <dd className="mt-1 text-2xl font-bold tracking-tight">{s.v}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  )
}

function FeatureGrid() {
  const t = useTranslations("landingPage.features")
  return (
    <section
      aria-labelledby="features-heading"
      className="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8"
    >
      <div className="mx-auto max-w-2xl text-center">
        <p className="text-sm font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
          {t("eyebrow")}
        </p>
        <h2
          id="features-heading"
          className="mt-3 text-balance text-3xl font-bold tracking-tight sm:text-4xl"
        >
          {t("heading")}
        </h2>
        <p className="mt-4 text-muted-foreground">
          {t("subtitle")}
        </p>
      </div>
      <StaggerContainer className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((f, index) => {
          const title = t(`${f.key}.title`)
          const body = t(`${f.key}.body`)
          
          // Bento Grid logic: alternate column spans to break visual monotony
          const bentoClass = index === 0 || index === 3 || index === 4 
            ? "sm:col-span-2 lg:col-span-2" 
            : "sm:col-span-1 lg:col-span-1"

          return (
            <StaggerItem
              key={f.key}
              className={cn(
                "group relative flex flex-col justify-between rounded-xl border bg-card/80 backdrop-blur-md p-6 lg:p-8 transition-all duration-300 hover:shadow-md hover:bg-card hover:border-primary/20",
                bentoClass
              )}
            >
              <div>
                <div className="flex items-center justify-between">
                  <div className="rounded-lg bg-primary/10 p-3">
                    <f.icon className="h-6 w-6 text-primary" aria-hidden="true" />
                  </div>
                  <span className="rounded-full border bg-background px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground shadow-sm">
                    {f.label}
                  </span>
                </div>
                <h3 className="mt-6 text-xl font-semibold tracking-tight">{title}</h3>
                <p className="mt-3 text-sm leading-relaxed text-muted-foreground">{body}</p>
              </div>
              <a
                href={f.href}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-6 inline-flex items-center gap-1.5 text-sm font-medium text-primary underline-offset-4 hover:underline"
              >
                {t("learnMore")}
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" aria-hidden="true" />
                <span className="sr-only"> {t("learnMoreAbout", { feature: title })}</span>
              </a>
            </StaggerItem>
          )
        })}
      </StaggerContainer>
    </section>
  )
}

function Showcase() {
  const t = useTranslations("landingPage.showcase")
  return (
    <section
      aria-label={t("ariaLabel")}
      className="border-y bg-gradient-to-b from-muted/20 to-transparent"
    >
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-balance text-3xl font-bold tracking-tight sm:text-4xl">
            {t("heading")}
          </h2>
          <p className="mt-4 text-muted-foreground">
            {t("subtitle")}
          </p>
        </div>
        <div className="mx-auto mt-12 max-w-5xl rounded-2xl border bg-card p-2 shadow-2xl shadow-blue-500/5 ring-1 ring-black/5 dark:ring-white/5">
          <div className="flex items-center gap-1.5 px-3 pt-2 pb-3">
            <span className="h-2.5 w-2.5 rounded-full bg-red-400" aria-hidden="true" />
            <span className="h-2.5 w-2.5 rounded-full bg-yellow-400" aria-hidden="true" />
            <span className="h-2.5 w-2.5 rounded-full bg-green-400" aria-hidden="true" />
            <span className="ml-auto text-[10px] font-mono text-muted-foreground">
              localhost:8077/dashboard
            </span>
          </div>
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/screenshot.png"
            alt={t("screenshotAlt")}
            width={1208}
            height={683}
            loading="lazy"
            decoding="async"
            className="w-full rounded-lg border"
          />
        </div>
      </div>
    </section>
  )
}

function HowItWorks() {
  const t = useTranslations("landingPage.how")
  return (
    <section
      aria-labelledby="how-heading"
      className="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8"
    >
      <div className="mx-auto max-w-2xl text-center">
        <p className="text-sm font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
          {t("eyebrow")}
        </p>
        <h2
          id="how-heading"
          className="mt-3 text-balance text-3xl font-bold tracking-tight sm:text-4xl"
        >
          {t("heading")}
        </h2>
      </div>
      <ol className="mx-auto mt-14 grid max-w-5xl gap-8 sm:grid-cols-3">
        {STEPS.map((key, i) => {
          const n = String(i + 1).padStart(2, "0")
          // step1 carries a CLI snippet; step2 + step3 are pure prose.
          const showCmd = key === "step1"
          return (
            <li key={key} className="relative flex flex-col rounded-xl border bg-card p-6">
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs font-semibold text-blue-600 dark:text-blue-400">
                  {n}
                </span>
                <span className="h-px flex-1 bg-border" aria-hidden="true" />
              </div>
              <h3 className="mt-4 text-lg font-semibold tracking-tight">{t(`${key}.title`)}</h3>
              <p className="mt-2 flex-1 text-sm text-muted-foreground">{t(`${key}.body`)}</p>
              {showCmd && (
                <pre className="mt-4 overflow-x-auto rounded-md bg-muted p-3 text-xs">
                  <code className="font-mono text-foreground">
                    <span className="text-muted-foreground">$ </span>
                    git clone … && make dev
                  </code>
                </pre>
              )}
            </li>
          )
        })}
      </ol>
    </section>
  )
}

function Audiences() {
  const t = useTranslations("landingPage.audiences")
  return (
    <section
      aria-labelledby="audiences-heading"
      className="border-y bg-muted/20"
    >
      <div className="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2
            id="audiences-heading"
            className="text-balance text-3xl font-bold tracking-tight sm:text-4xl"
          >
            {t("heading")}
          </h2>
          <p className="mt-4 text-muted-foreground">{t("subtitle")}</p>
        </div>
        <div className="mx-auto mt-14 grid max-w-5xl gap-6 sm:grid-cols-2">
          {AUDIENCES.map((key) => (
            <div key={key} className="rounded-xl border bg-card p-6">
              <p className="text-sm font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
                {t("for", { role: t(`${key}.role`) })}
              </p>
              <p className="mt-3 text-sm text-muted-foreground">{t(`${key}.body`)}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

function SelfHosted() {
  const t = useTranslations("landingPage.selfHosted")
  // The single most important architectural commitment of this
  // project: your scan data, asset inventory, and vulnerability
  // reports never leave your perimeter. Calling that out as a
  // section, not a bullet, because it's the entire reason a CISO of
  // an essential entity will look at this.
  const points: ReadonlyArray<string> = [
    t("point1"),
    t("point2"),
    t("point3"),
    t("point4"),
  ]
  // The {cmd} placeholder in `production` is replaced with a styled
  // <code> tag at render time using rich-text formatting from
  // next-intl's t.rich(). Keeping the markup outside the JSON keeps
  // translators from accidentally breaking the styling.
  // The translator-supplied `prose` here is concatenation-safe across
  // RTL/LTR and across "Production:" prefix wording (DE puts "in
  // production" after the colon, IT before, etc).
  return (
    <section
      aria-labelledby="self-hosted-heading"
      className="mx-auto max-w-7xl px-4 py-20 sm:px-6 sm:py-24 lg:px-8"
    >
      <div className="mx-auto grid max-w-6xl gap-12 lg:grid-cols-2 lg:items-center">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border bg-card px-3 py-1 text-xs font-medium text-muted-foreground">
            <Lock className="h-3 w-3" aria-hidden="true" />
            {t("badge")}
          </div>
          <h2
            id="self-hosted-heading"
            className="mt-4 text-balance text-3xl font-bold tracking-tight sm:text-4xl"
          >
            {t("heading")}
          </h2>
          <p className="mt-4 text-muted-foreground">{t("subtitle")}</p>
          <ul className="mt-8 space-y-3">
            {points.map((p) => (
              <li key={p} className="flex items-start gap-3 text-sm">
                <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                <span className="text-muted-foreground">{p}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-2xl border bg-card p-6 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {t("techStack")}
          </p>
          <ul className="mt-4 flex flex-wrap gap-2">
            {STACK.map((s) => (
              <li
                key={s}
                className="rounded-full border bg-background px-3 py-1 text-xs font-medium"
              >
                {s}
              </li>
            ))}
          </ul>
          <p className="mt-8 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {t("runIt")}
          </p>
          <pre className="mt-4 overflow-x-auto rounded-lg bg-muted p-4 text-xs leading-relaxed">
            <code className="font-mono">
              <span className="text-muted-foreground"># {t("snippetIntro")}</span>
              {"\n"}
              <span className="text-muted-foreground">$</span> git clone https://github.com/fabriziosalmi/nis2-public.git
              {"\n"}
              <span className="text-muted-foreground">$</span> cd nis2-public
              {"\n"}
              <span className="text-muted-foreground">$</span> cp .env.example .env
              {"\n"}
              <span className="text-muted-foreground">$</span> make dev
            </code>
          </pre>
          <p className="mt-3 text-xs text-muted-foreground">
            {/* `production` carries a <cmd>make prod</cmd> tag in every
                locale; t.rich injects a styled <code> in its place so
                the command is visually distinct without baking the JSX
                tag name into the translation files. */}
            {t.rich("production", {
              cmd: (chunks) => <code className="font-mono">{chunks}</code>,
            })}
          </p>
        </div>
      </div>
    </section>
  )
}

function FinalCta() {
  const t = useTranslations("landingPage.finalCta")
  return (
    <section className="border-t">
      <div className="mx-auto max-w-7xl px-4 py-24 sm:px-6 lg:px-8">
        <div className="relative overflow-hidden rounded-3xl border bg-gradient-to-br from-primary to-primary/80 p-10 text-center text-primary-foreground sm:p-16">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(80%_60%_at_50%_0%,rgba(255,255,255,0.15),transparent_70%)]"
          />
          <h2 className="text-balance text-3xl font-bold tracking-tight sm:text-4xl">
            {t("heading")}
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-pretty text-primary-foreground/80">
            {t("subtitle")}
          </p>
          <div className="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
            <Button asChild size="lg" variant="secondary" className="w-full sm:w-auto">
              <Link href="/register">
                {t("create")}
                <ArrowRight className="h-4 w-4" aria-hidden="true" />
              </Link>
            </Button>
            <Button
              asChild
              size="lg"
              variant="outline"
              className="w-full border-primary-foreground/30 bg-transparent text-primary-foreground hover:bg-primary-foreground/10 hover:text-primary-foreground sm:w-auto"
            >
              <a
                href="https://github.com/fabriziosalmi/nis2-public#readme"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Terminal className="h-4 w-4" aria-hidden="true" />
                {t("readDocs")}
              </a>
            </Button>
          </div>
        </div>
      </div>
    </section>
  )
}

function SiteFooter() {
  const t = useTranslations("landingPage.footer")
  return (
    <footer className="border-t bg-background">
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
          <div className="sm:col-span-2">
            <Link href="/" className="flex items-center gap-2.5">
              <Logo size={28} />
              <span className="font-semibold tracking-tight">NIS2 Platform</span>
            </Link>
            <p className="mt-4 max-w-md text-sm text-muted-foreground">
              {t("blurbStart")}{" "}
              <a
                href="mailto:fabrizio.salmi@gmail.com"
                className="font-medium text-foreground underline-offset-4 hover:underline"
              >
                {t("blurbAuthor")}
              </a>
              , {t("blurbEnd")}
            </p>
          </div>
          <FooterColumn
            title={t("project")}
            links={[
              { label: t("github"), href: "https://github.com/fabriziosalmi/nis2-public", icon: Github, external: true },
              { label: t("readme"), href: "https://github.com/fabriziosalmi/nis2-public#readme", external: true },
              { label: t("license"), href: "https://github.com/fabriziosalmi/nis2-public/blob/main/LICENSE", external: true },
              { label: t("security"), href: "https://github.com/fabriziosalmi/nis2-public/blob/main/SECURITY.md", external: true },
            ]}
          />
          <FooterColumn
            title={t("platform")}
            links={[
              { label: t("signIn"), href: "/login" },
              { label: t("getStarted"), href: "/register" },
              { label: t("forgot"), href: "/forgot-password" },
              { label: t("contact"), href: "mailto:fabrizio.salmi@gmail.com" },
              // v2.5.0 legal-review: privacy + terms must be reachable
              // from the public footer (Art. 13 GDPR + Art. 7-12
              // D.Lgs 70/2003 — operator info + privacy notice
              // accessibility from every page of a commercial site).
              { label: t("privacy"), href: "https://github.com/fabriziosalmi/nis2-public/blob/main/docs/privacy.md", external: true },
              { label: t("terms"), href: "https://github.com/fabriziosalmi/nis2-public/blob/main/docs/terms.md", external: true },
            ]}
          />
        </div>
        <div className="mt-12 flex flex-col items-start gap-4 border-t pt-8 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs text-muted-foreground">{t("copyright")}</p>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <Server className="h-3 w-3" aria-hidden="true" /> {t("selfHosted")}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Globe className="h-3 w-3" aria-hidden="true" /> {t("fiveLanguages")}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Code2 className="h-3 w-3" aria-hidden="true" /> {t("license2")}
            </span>
          </div>
        </div>
      </div>
    </footer>
  )
}

function FooterColumn({
  title,
  links,
}: {
  title: string
  links: ReadonlyArray<{
    label: string
    href: string
    external?: boolean
    icon?: React.ComponentType<{ className?: string; "aria-hidden"?: boolean | "true" | "false" }>
  }>
}) {
  return (
    <div>
      <h3 className="text-sm font-semibold tracking-tight">{title}</h3>
      <ul className="mt-4 space-y-3">
        {links.map((l) => (
          <li key={l.label}>
            {l.external ? (
              <a
                href={l.href}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground"
              >
                {l.icon && <l.icon className="h-3.5 w-3.5" aria-hidden="true" />}
                {l.label}
              </a>
            ) : (
              <Link
                href={l.href}
                className="text-sm text-muted-foreground transition-colors hover:text-foreground"
              >
                {l.label}
              </Link>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}
