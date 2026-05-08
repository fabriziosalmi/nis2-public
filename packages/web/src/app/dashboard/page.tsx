// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import React, { useEffect, useState } from "react"
import Link from "next/link"
import dynamic from "next/dynamic"
import { Radar, ShieldCheck, AlertTriangle, Server, Plus, ArrowUpRight, CheckCircle2, XCircle, Info, X } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useScans } from "@/hooks/use-scans"
import { useFindingStats } from "@/hooks/use-findings"
import { useAssets } from "@/hooks/use-assets"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

// Lazy load Recharts (400KB+) — only loads when charts are visible.
// The `as any` + explicit ComponentType<any> cast is required because
// next/dynamic wraps the named export and loses the original prop
// types. Without this, strict TS (P1-08) rejects JSX props like
// `width`, `height`, `children` on the dynamically loaded component.
/* eslint-disable @typescript-eslint/no-explicit-any */
const BarChart = dynamic(() => import("recharts").then(m => m.BarChart as any), { ssr: false }) as React.ComponentType<any>
const Bar = dynamic(() => import("recharts").then(m => m.Bar as any), { ssr: false }) as React.ComponentType<any>
const XAxis = dynamic(() => import("recharts").then(m => m.XAxis as any), { ssr: false }) as React.ComponentType<any>
const YAxis = dynamic(() => import("recharts").then(m => m.YAxis as any), { ssr: false }) as React.ComponentType<any>
const CartesianGrid = dynamic(() => import("recharts").then(m => m.CartesianGrid as any), { ssr: false }) as React.ComponentType<any>
const Tooltip = dynamic(() => import("recharts").then(m => m.Tooltip as any), { ssr: false }) as React.ComponentType<any>
const ResponsiveContainer = dynamic(() => import("recharts").then(m => m.ResponsiveContainer as any), { ssr: false }) as React.ComponentType<any>
const LineChart = dynamic(() => import("recharts").then(m => m.LineChart as any), { ssr: false }) as React.ComponentType<any>
const Line = dynamic(() => import("recharts").then(m => m.Line as any), { ssr: false }) as React.ComponentType<any>
/* eslint-enable @typescript-eslint/no-explicit-any */
import { useFormatDate } from "@/lib/dates"

function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, string> = {
    pending: "border-yellow-500 text-yellow-600 bg-yellow-50",
    running: "border-blue-500 text-blue-600 bg-blue-50 animate-pulse",
    completed: "border-green-500 text-green-600 bg-green-50",
    failed: "border-red-500 text-red-600 bg-red-50",
  }
  // Lookup is namespaced to `scans` because the same status enum drives
  // the /scans table — same labels, same colours, one source of truth.
  const ts = useTranslations("scans")
  return (
    <Badge variant="outline" className={variants[status] || ""}>
      {ts(status as any)}
    </Badge>
  )
}

// v2.4.23 audit a11y-05 (WCAG SC 1.4.1 Use of Color): the score
// previously communicated band ("good" / "fair" / "poor") *only*
// through the green / yellow / red text colour. That fails for
// users with deuteranopia / protanopia (red-green color blindness)
// and also for greyscale prints. Adding a band-specific icon
// prefix (✓ / ! / ✗) ensures the rating is recognisable without
// colour, and the aria-label makes the band name explicit for SR.
function ScoreDisplay({ score }: { score: number | null | undefined }) {
  if (score === null || score === undefined) return <span className="text-muted-foreground">--</span>
  const band = score > 80 ? "good" : score > 60 ? "fair" : "poor"
  const Icon = band === "good" ? CheckCircle2 : band === "fair" ? AlertTriangle : XCircle
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 font-bold",
        band === "good" ? "text-green-600" : band === "fair" ? "text-yellow-600" : "text-red-600"
      )}
      aria-label={`${score} (${band})`}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      <span>{score}</span>
    </span>
  )
}

// v2.5.3 (DAVIDE-4): orientation card. Davide opened a fresh clone, ran
// `make dev`, signed up, landed on /dashboard, and could not figure out
// what the platform was actually *for* — the empty stat cards and the
// "New Scan" CTA gave no hint of the link between a TLS/DNS/header
// scan and the Art. 21(2) sub-paragraphs the result eventually weakens.
//
// This card is the missing 30-second orientation: what the three
// surfaces (Scans, Governance, Vendors) cover, which Article maps to
// which surface, and that the scanner is ~30 % of Art. 21 and Art. 18
// is tracked separately. Dismissible — once the user has internalised
// the mapping, the card stays out of the way. Versioned key so a
// future rewrite (e.g. a new surface added) re-shows it.
const ORIENTATION_KEY = "nis2-dashboard-orientation-v1"

function OrientationCard() {
  const t = useTranslations("dashboard")
  const [mounted, setMounted] = useState(false)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    setMounted(true)
    try {
      if (localStorage.getItem(ORIENTATION_KEY) === "dismissed") {
        setDismissed(true)
      }
    } catch {
      // localStorage unavailable — show the card; user can dismiss it
      // for the session even if the choice can't be persisted.
    }
  }, [])

  const handleDismiss = () => {
    try {
      localStorage.setItem(ORIENTATION_KEY, "dismissed")
    } catch {
      /* no persistence — re-shows next visit, acceptable */
    }
    setDismissed(true)
  }

  // Same SSR-empty-tree pattern as LegalDisclaimerModal — render
  // nothing on the server so a stale localStorage state can't produce
  // a hydration mismatch.
  if (!mounted) return null
  if (dismissed) return null

  // Mark `<b>` from the translation strings as bold spans. Using
  // t.rich() keeps the markup in code (not in the JSON) and lets
  // next-intl validate the placeholders at compile time.
  const bold = (chunks: React.ReactNode) => <strong className="font-semibold text-foreground">{chunks}</strong>

  return (
    <Card className="border-blue-500/30 bg-blue-500/5 dark:bg-blue-500/10">
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-3">
        <div className="flex items-start gap-3">
          <div className="rounded-lg bg-blue-500/10 p-2">
            <Info className="h-4 w-4 text-blue-600" aria-hidden="true" />
          </div>
          <CardTitle className="text-base font-semibold leading-tight pt-1">
            {t("orientationTitle")}
          </CardTitle>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleDismiss}
          aria-label={t("orientationDismiss")}
          className="h-8 w-8 shrink-0 p-0 text-muted-foreground hover:text-foreground"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 text-sm leading-relaxed text-muted-foreground">
        <p>{t("orientationIntro")}</p>
        <ul className="space-y-2 list-disc pl-5">
          <li>{t.rich("orientationScans", { b: bold })}</li>
          <li>{t.rich("orientationGovernance", { b: bold })}</li>
          <li>{t.rich("orientationVendors", { b: bold })}</li>
        </ul>
        <div className="flex flex-wrap gap-2 pt-2">
          <Button asChild variant="outline" size="sm">
            <Link href="/dashboard/compliance">
              {t("orientationCta")}
              <ArrowUpRight className="ml-1 h-3.5 w-3.5" aria-hidden="true" />
            </Link>
          </Button>
          <Button variant="ghost" size="sm" onClick={handleDismiss}>
            {t("orientationDismiss")}
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

export default function DashboardPage() {
  // v2.4.15 audit B-DRA-03: this landing page used to render every
  // string hardcoded in English, even though the `dashboard` namespace
  // in messages/*.json already had keys for almost everything. Wiring
  // up `useTranslations` here closes the gap for IT/FR/DE/ES users
  // without adding new translations on the existing keys.
  const t = useTranslations("dashboard")
  // Severity labels (Critical/High/Medium/Low) live in the `findings`
  // namespace; reuse those rather than mint duplicates.
  const tf = useTranslations("findings")
  const tc = useTranslations("common")
  // v2.4.17 audit S-DRA-01: replaces direct `date-fns format()` calls
  // so dates render in the user's active locale (IT / FR / DE / ES)
  // rather than always en-US.
  const formatDate = useFormatDate()
  // v2.4.24 audit a11y-11: per-page <title> via document.title.
  useDocumentTitle(t("title"))

  const { data: scansData, isLoading: scansLoading } = useScans()
  const { data: statsData } = useFindingStats()
  const { data: assetsData } = useAssets()

  const scans = scansData?.items || []
  const recentScans = scans.slice(0, 5)
  const hasData = scans.length > 0

  // Compute real stats
  const completedScans = scans.filter((s: any) => s.status === "completed" && s.total_score != null)
  const avgScore = completedScans.length > 0
    ? Math.round(completedScans.reduce((sum: number, s: any) => sum + s.total_score, 0) / completedScans.length)
    : null

  const totalFindings = scans.reduce((sum: number, s: any) =>
    sum + (s.findings_critical || 0) + (s.findings_high || 0) + (s.findings_medium || 0) + (s.findings_low || 0), 0)

  // Build chart data from real scans. Severity labels come from the
  // findings namespace so the chart axis localises with the rest of
  // the UI.
  const severityChartData = hasData ? [
    { severity: tf("critical"), count: scans.reduce((s: number, sc: any) => s + (sc.findings_critical || 0), 0) },
    { severity: tf("high"), count: scans.reduce((s: number, sc: any) => s + (sc.findings_high || 0), 0) },
    { severity: tf("medium"), count: scans.reduce((s: number, sc: any) => s + (sc.findings_medium || 0), 0) },
    { severity: tf("low"), count: scans.reduce((s: number, sc: any) => s + (sc.findings_low || 0), 0) },
  ] : []

  const trendData = completedScans
    .sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    .map((s: any) => ({
      // "MMM d" intentionally hardcoded — the trend chart's X axis
      // benefits from a compact label that doesn't blow out the
      // tick spacing, regardless of locale verbosity. The full
      // localised date appears in the table cells below.
      date: formatDate(s.created_at, "MMM d"),
      score: s.total_score,
    }))

  const stats = [
    {
      title: t("totalScans"),
      value: scansData?.total?.toString() || "0",
      change: completedScans.length > 0
        ? t("completed", { count: completedScans.length })
        : t("noScansYet"),
      icon: Radar,
      bg: "bg-blue-500/10",
      iconColor: "text-blue-600",
    },
    {
      title: t("averageScore"),
      value: avgScore?.toString() || "--",
      change: avgScore
        ? avgScore > 80
          ? t("goodCompliance")
          : avgScore > 60
            ? t("needsImprovement")
            : t("actionRequired")
        : t("runAScan"),
      icon: ShieldCheck,
      bg: "bg-green-500/10",
      iconColor: "text-green-600",
    },
    {
      title: t("totalFindings"),
      value: totalFindings.toString(),
      change: statsData?.open
        ? t("openFindings", { count: statsData.open })
        : t("acrossAllScans"),
      icon: AlertTriangle,
      bg: "bg-orange-500/10",
      iconColor: "text-orange-600",
    },
    {
      title: t("assetsMonitored"),
      value: assetsData?.total?.toString() || "0",
      change: assetsData?.total > 0 ? t("activeTargets") : t("addAssetsToStart"),
      icon: Server,
      bg: "bg-purple-500/10",
      iconColor: "text-purple-600",
    },
  ]

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Button asChild className="shrink-0 w-fit">
          <Link href="/dashboard/scans/new">
            <Plus className="mr-2 h-4 w-4" />
            {t("newScan")}
          </Link>
        </Button>
      </div>

      <OrientationCard />

      {/* Stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.title}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <div className={cn("rounded-lg p-2", stat.bg)}>
                <stat.icon className={cn("h-4 w-4", stat.iconColor)} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stat.value}</div>
              <p className="text-xs text-muted-foreground">{stat.change}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts row - only show when there's data */}
      {hasData && (
        <div className="grid gap-4 lg:grid-cols-7">
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle>{t("findingsBySeverity")}</CardTitle>
              <CardDescription>{t("severityDistribution")}</CardDescription>
            </CardHeader>
            <CardContent>
              {/* v2.4.23 audit a11y-16 (WCAG SC 1.1.1 Non-text Content):
                  Recharts renders SVG with no programmatic data
                  exposed to AT. Wrapping the chart in a labelled
                  region gives the visualisation a name + role, and
                  the sr-only data table below offers an equivalent
                  textual representation that SR users can read. */}
              {severityChartData.some((d) => d.count > 0) ? (
                <div role="img" aria-label={t("findingsBySeverity")}>
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={severityChartData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                      <XAxis type="number" />
                      <YAxis dataKey="severity" type="category" width={70} tick={{ fontSize: 12 }} />
                      <Tooltip contentStyle={{ borderRadius: "8px" }} />
                      <Bar dataKey="count" radius={[0, 4, 4, 0]} fill="hsl(222.2, 47.4%, 11.2%)" />
                    </BarChart>
                  </ResponsiveContainer>
                  <table className="sr-only">
                    <caption>{t("findingsBySeverity")}</caption>
                    <thead>
                      <tr>
                        <th>{tf("severity")}</th>
                        <th>{t("findingsColumn")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {severityChartData.map((d) => (
                        <tr key={d.severity}>
                          <td>{d.severity}</td>
                          <td>{d.count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="flex items-center justify-center h-[260px] text-muted-foreground text-sm">{t("noFindingsData")}</div>
              )}
            </CardContent>
          </Card>

          <Card className="lg:col-span-4">
            <CardHeader>
              <CardTitle>{t("complianceScoreTrend")}</CardTitle>
              <CardDescription>{t("scoreProgression")}</CardDescription>
            </CardHeader>
            <CardContent>
              {trendData.length > 1 ? (
                <div role="img" aria-label={t("complianceScoreTrend")}>
                  <ResponsiveContainer width="100%" height={260}>
                    <LineChart data={trendData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
                      <Tooltip contentStyle={{ borderRadius: "8px" }} />
                      <Line type="monotone" dataKey="score" stroke="hsl(222.2, 47.4%, 11.2%)" strokeWidth={2} dot={{ r: 3 }} activeDot={{ r: 5 }} />
                    </LineChart>
                  </ResponsiveContainer>
                  <table className="sr-only">
                    <caption>{t("complianceScoreTrend")}</caption>
                    <thead>
                      <tr>
                        <th>{t("date")}</th>
                        <th>{t("score")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {trendData.map((d: any, i: number) => (
                        <tr key={i}>
                          <td>{d.date}</td>
                          <td>{d.score}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="flex items-center justify-center h-[260px] text-muted-foreground text-sm">
                  {trendData.length === 1 ? t("needTwoScans") : t("noCompletedScans")}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Getting started - show when no data */}
      {!hasData && !scansLoading && (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <div className="rounded-full bg-primary/10 p-4 mb-4">
              <ShieldCheck className="h-10 w-10 text-primary" />
            </div>
            <h3 className="text-xl font-semibold mb-2">{t("welcome")}</h3>
            <p className="text-muted-foreground mb-6 max-w-md">{t("welcomeDescription")}</p>
            <div className="flex gap-3">
              <Button variant="outline" asChild>
                <Link href="/dashboard/assets">
                  <Server className="mr-2 h-4 w-4" />
                  {t("addAssets")}
                </Link>
              </Button>
              <Button asChild>
                <Link href="/dashboard/scans/new">
                  <Radar className="mr-2 h-4 w-4" />
                  {t("runFirstScan")}
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recent scans */}
      {recentScans.length > 0 && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>{t("recentScans")}</CardTitle>
              <CardDescription>{t("recentScansDescription")}</CardDescription>
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link href="/dashboard/scans">
                {tc("viewAll")}
                <ArrowUpRight className="ml-1 h-3 w-3" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("name")}</TableHead>
                  <TableHead>{t("status")}</TableHead>
                  <TableHead>{t("score")}</TableHead>
                  <TableHead>{t("findingsColumn")}</TableHead>
                  <TableHead>{t("date")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentScans.map((scan: any) => (
                  <TableRow key={scan.id} className="cursor-pointer">
                    <TableCell className="font-medium">
                      <Link href={`/dashboard/scans/${scan.id}`} className="hover:underline">{scan.name}</Link>
                    </TableCell>
                    <TableCell><StatusBadge status={scan.status} /></TableCell>
                    <TableCell><ScoreDisplay score={scan.total_score} /></TableCell>
                    <TableCell>{(scan.findings_critical || 0) + (scan.findings_high || 0) + (scan.findings_medium || 0) + (scan.findings_low || 0)}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatDate(scan.created_at, "PP")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Professional services CTA */}
      <Card className="bg-muted/30 border-muted">
        <CardContent className="flex flex-col sm:flex-row items-center justify-between gap-4 py-5">
          <div>
            <p className="text-sm font-medium">{t("needExpertHelp")}</p>
            <p className="text-xs text-muted-foreground">{t("needExpertDescription")}</p>
          </div>
          <Button variant="outline" size="sm" asChild className="shrink-0">
            <a href="mailto:fabrizio.salmi@gmail.com">
              {t("requestConsultation")}
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
