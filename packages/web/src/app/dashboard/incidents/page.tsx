// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect, useState } from "react"
import { useTranslations } from "next-intl"
import { Siren, Clock, CheckCircle2, AlertOctagon, Loader2, ShieldAlert } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useIncidentMonitor } from "@/hooks/use-incidents"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

const severityVariant: Record<string, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
}

// Format a signed millisecond delta as "Dd HH:MM:SS" (or "HH:MM:SS" under a day).
function fmt(ms: number): string {
  const neg = ms < 0
  let s = Math.floor(Math.abs(ms) / 1000)
  const d = Math.floor(s / 86400); s %= 86400
  const h = Math.floor(s / 3600); s %= 3600
  const m = Math.floor(s / 60); s %= 60
  const pad = (n: number) => String(n).padStart(2, "0")
  const core = d > 0 ? `${d}d ${pad(h)}:${pad(m)}:${pad(s)}` : `${pad(h)}:${pad(m)}:${pad(s)}`
  return (neg ? "-" : "") + core
}

interface Deadline {
  label: string
  deadline: string | null
  sent_at: string | null
}

function DeadlineChip({
  title,
  deadline,
  isOpen,
  nowMs,
}: {
  title: string
  deadline: Deadline
  isOpen: boolean
  nowMs: number
}) {
  const t = useTranslations("incidents")
  if (!deadline.deadline) return null

  const remainingMs = new Date(deadline.deadline).getTime() - nowMs
  const sent = !!deadline.sent_at
  const overdue = isOpen && !sent && remainingMs < 0
  const urgent = isOpen && !sent && remainingMs >= 0 && remainingMs < 6 * 3600_000

  const tone = sent
    ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400"
    : overdue
      ? "border-destructive/50 bg-destructive/10 text-destructive"
      : urgent
        ? "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-border bg-muted/40 text-foreground"

  return (
    <div className={cn("flex flex-col gap-1 rounded-lg border px-3 py-2 min-w-[9.5rem]", tone)}>
      <span className="text-[11px] font-medium uppercase tracking-wide opacity-80">{title}</span>
      <div className="flex items-center gap-1.5">
        {sent ? (
          <>
            <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="text-sm font-semibold">{t("sent")}</span>
          </>
        ) : overdue ? (
          <>
            <AlertOctagon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="font-mono text-sm font-semibold tabular-nums">{fmt(remainingMs)}</span>
          </>
        ) : (
          <>
            <Clock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="font-mono text-sm font-semibold tabular-nums">{fmt(remainingMs)}</span>
          </>
        )}
      </div>
      <span className="text-[10px] opacity-70">
        {sent ? "" : overdue ? t("deadlinePassed") : t("remaining")}
      </span>
    </div>
  )
}

export default function IncidentsPage() {
  const t = useTranslations("incidents")
  useDocumentTitle(t("title"))

  const { data, isLoading } = useIncidentMonitor()

  // Live clock — re-render every second so the countdowns tick.
  const [nowMs, setNowMs] = useState<number>(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const items: any[] = data?.items ?? []
  const openCount = data?.open_count ?? 0
  const breachedCount = data?.breached_count ?? 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <Siren className="h-6 w-6 text-primary" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        </div>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      {/* Summary */}
      <div className="grid gap-4 sm:grid-cols-2 lg:max-w-xl">
        <Card>
          <CardContent className="flex items-center gap-4 py-5">
            <div className="rounded-full bg-primary/10 p-3">
              <Siren className="h-5 w-5 text-primary" aria-hidden="true" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums">{openCount}</p>
              <p className="text-sm text-muted-foreground">{t("openNow")}</p>
            </div>
          </CardContent>
        </Card>
        <Card className={cn(breachedCount > 0 && "border-destructive/40")}>
          <CardContent className="flex items-center gap-4 py-5">
            <div className={cn("rounded-full p-3", breachedCount > 0 ? "bg-destructive/10" : "bg-emerald-500/10")}>
              <AlertOctagon className={cn("h-5 w-5", breachedCount > 0 ? "text-destructive" : "text-emerald-600")} aria-hidden="true" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums">{breachedCount}</p>
              <p className="text-sm text-muted-foreground">
                {breachedCount > 0 ? t("atRisk") : t("allClear")}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-20 text-center">
            <div className="rounded-full border border-primary/20 bg-primary/5 p-6 mb-5">
              <ShieldAlert className="h-9 w-9 text-primary opacity-80" aria-hidden="true" />
            </div>
            <h3 className="text-xl font-semibold mb-1.5">{t("noIncidents")}</h3>
            <p className="text-muted-foreground max-w-md">{t("noIncidentsDesc")}</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {items.map((inc) => {
            const detected = new Date(inc.detected_at)
            const dl: Record<string, Deadline> = Object.fromEntries(
              (inc.deadlines as Deadline[]).map((d) => [d.label, d])
            )
            return (
              <Card key={inc.id} className={cn(inc.is_open && inc.severity === "critical" && "border-destructive/30")}>
                <CardHeader className="pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <CardTitle className="text-base">{inc.title}</CardTitle>
                    <Badge variant={severityVariant[inc.severity] ?? "medium"}>
                      {t(`sev_${inc.severity}`)}
                    </Badge>
                    <Badge variant="outline">{t(`st_${inc.status}`)}</Badge>
                    {inc.supply_chain_impact && (
                      <Badge variant="secondary">Art. 18</Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {t("detected")}: {detected.toLocaleString()}
                    {inc.affected_systems ? ` · ${inc.affected_systems}` : ""}
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-3">
                    <DeadlineChip title={`${t("earlyWarning")} · 24h`} deadline={dl.early_warning} isOpen={inc.is_open} nowMs={nowMs} />
                    <DeadlineChip title={`${t("notification")} · 72h`} deadline={dl.notification} isOpen={inc.is_open} nowMs={nowMs} />
                    <DeadlineChip title={`${t("finalReport")} · 1M`} deadline={dl.final_report} isOpen={inc.is_open} nowMs={nowMs} />
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
