// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// The regulatory countdown: D.Lgs 138/2024 and the ACN determine.
//
// GET /api/v1/deadlines has always returned this — the dates, the days
// remaining and an urgency band per obligation — and nothing in the product
// ever called it. For an Italian in-scope entity these are the dates that
// decide whether they are compliant or exposed, and they were reachable only
// by someone reading the OpenAPI schema.
//
// The titles and descriptions come from the API in Italian, because they name
// Italian regulatory instruments ("Determina ACN 127437/2026") that have no
// translation. Only the interface chrome around them is localised.

"use client"

import { useQuery } from "@tanstack/react-query"
import { useTranslations } from "next-intl"
import { CalendarClock, AlertOctagon, Loader2 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"
import { cn } from "@/lib/utils"

/** One row of GET /api/v1/deadlines. */
interface RegulatoryDeadline {
  id: string
  title: string
  description: string
  article?: string
  deadline: string
  days_remaining: number
  urgency: string
}

const URGENCY_TONE: Record<string, string> = {
  overdue: "border-destructive/50 bg-destructive/5",
  critical: "border-destructive/40 bg-destructive/5",
  urgent: "border-amber-500/40 bg-amber-500/5",
  warning: "border-amber-500/25",
  on_track: "border-border",
}

const URGENCY_VARIANT: Record<string, "critical" | "high" | "medium" | "info"> = {
  overdue: "critical",
  critical: "critical",
  urgent: "high",
  warning: "medium",
  on_track: "info",
}

export function RegulatoryDeadlines() {
  const t = useTranslations("compliancePage.deadlines")
  const user = useAuthStore((s) => s.user)
  const { data, isLoading } = useQuery({
    queryKey: ["compliance-deadlines"],
    queryFn: () => api.getComplianceDeadlines(),
    enabled: !!user,
    // These move once a day at most.
    staleTime: 60 * 60 * 1000,
  })

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
        </CardContent>
      </Card>
    )
  }

  const deadlines: RegulatoryDeadline[] = data?.deadlines ?? []
  if (deadlines.length === 0) return null

  const overdue = data?.overdue_count ?? 0

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <CalendarClock className="h-5 w-5 text-primary" aria-hidden="true" />
          <CardTitle className="text-base">{t("title")}</CardTitle>
          {overdue > 0 && (
            <Badge variant="critical" className="ml-auto">
              <AlertOctagon className="mr-1 h-3 w-3" aria-hidden="true" />
              {t("overdueCount", { count: overdue })}
            </Badge>
          )}
        </div>
        <p className="text-sm text-muted-foreground">{t("subtitle")}</p>
      </CardHeader>
      <CardContent>
        <ul className="space-y-3">
          {deadlines.map((d) => (
            <li
              key={d.id}
              className={cn("rounded-lg border px-4 py-3", URGENCY_TONE[d.urgency] ?? "border-border")}
            >
              <div className="flex flex-wrap items-start gap-2">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{d.title}</p>
                  <p className="mt-0.5 text-sm text-muted-foreground">{d.description}</p>
                  {d.article && (
                    <p className="mt-1 text-xs text-muted-foreground">{d.article}</p>
                  )}
                </div>
                <div className="shrink-0 text-right">
                  <Badge variant={URGENCY_VARIANT[d.urgency] ?? "info"}>
                    {t(`urgency_${d.urgency}`)}
                  </Badge>
                  <p className="mt-1 font-mono text-sm tabular-nums">
                    {new Date(d.deadline).toLocaleDateString()}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {d.days_remaining < 0
                      ? t("daysOverdue", { count: Math.abs(d.days_remaining) })
                      : t("daysRemaining", { count: d.days_remaining })}
                  </p>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}
