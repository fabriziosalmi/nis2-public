// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useTranslations } from "next-intl"
import { toast } from "sonner"
import { ClipboardCheck, RefreshCw, Loader2, Radar, ListChecks } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useGovernance, useGovernanceScore, useSyncRisk, useSeedGovernance } from "@/hooks/use-governance"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

const priorityVariant: Record<string, "critical" | "high" | "medium"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
}

// status → { label key, dot color, text color }
const statusStyle: Record<string, { key: string; dot: string; text: string }> = {
  done: { key: "done", dot: "bg-emerald-500", text: "text-emerald-600 dark:text-emerald-400" },
  in_progress: { key: "inProgress", dot: "bg-amber-500", text: "text-amber-600 dark:text-amber-400" },
  not_started: { key: "notStarted", dot: "bg-muted-foreground/40", text: "text-muted-foreground" },
  not_applicable: { key: "notApplicable", dot: "bg-muted-foreground/30", text: "text-muted-foreground" },
}

function ScoreBar({ label, pct, done, total }: { label: string; pct: number; done: number; total: number }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="font-medium">{label}</span>
        <span className="text-muted-foreground tabular-nums">{done}/{total}</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${Math.round(pct)}%` }} />
      </div>
    </div>
  )
}

export default function GovernancePage() {
  const t = useTranslations("governance")
  useDocumentTitle(t("title"))

  const { data: list, isLoading } = useGovernance()
  const { data: score } = useGovernanceScore()
  const sync = useSyncRisk()
  const seed = useSeedGovernance()

  const items: any[] = list?.items ?? []
  const stats = list?.stats
  const byPriority = score?.by_priority ?? {}

  const onSync = () => {
    sync.mutate(undefined, {
      onSuccess: (res: any) => {
        if ((res?.updated ?? 0) > 0) toast.success(t("syncRiskDone", { count: res.updated }))
        else toast.info(t("syncRiskNone"))
      },
      onError: (e: any) => toast.error(e?.message || "Sync failed"),
    })
  }

  const onSeed = () => {
    seed.mutate(undefined, {
      onError: (e: any) => toast.error(e?.message || "Init failed"),
    })
  }

  const notSeeded = !isLoading && items.length === 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <ClipboardCheck className="h-6 w-6 text-primary" aria-hidden="true" />
            <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
          </div>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        {!notSeeded && (
          <Button onClick={onSync} disabled={sync.isPending}>
            {sync.isPending ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" aria-hidden="true" />
            )}
            {t("syncRisk")}
          </Button>
        )}
      </div>

      {notSeeded ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-20 text-center">
            <div className="rounded-full border border-primary/20 bg-primary/5 p-6 mb-5">
              <ListChecks className="h-9 w-9 text-primary opacity-80" aria-hidden="true" />
            </div>
            <h3 className="text-xl font-semibold mb-1.5">{t("noItems")}</h3>
            <p className="text-muted-foreground max-w-md mb-5">{t("initChecklistDesc")}</p>
            <Button onClick={onSeed} disabled={seed.isPending}>
              {seed.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />}
              {t("initChecklist")}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <>
          {/* Score + sync explainer */}
          <div className="grid gap-4 lg:grid-cols-3">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">{t("weightedScore")}</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-baseline gap-1">
                  <span className="text-4xl font-bold tabular-nums">{Math.round(score?.score ?? stats?.completion_pct ?? 0)}</span>
                  <span className="text-lg text-muted-foreground">/100</span>
                </div>
              </CardContent>
            </Card>
            <Card className="lg:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">{t("checklist")}</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {["CRITICAL", "HIGH", "MEDIUM"].map((p) => {
                  const bp = byPriority[p]
                  if (!bp) return null
                  const labelKey = p === "CRITICAL" ? "prCritical" : p === "HIGH" ? "prHigh" : "prMedium"
                  return <ScoreBar key={p} label={t(labelKey)} pct={bp.pct} done={bp.done} total={bp.total} />
                })}
              </CardContent>
            </Card>
          </div>

          {/* Checklist table */}
          <Card>
            <CardContent className="p-0">
              {isLoading ? (
                <div className="flex items-center justify-center py-16">
                  <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-16">{t("itemCol")}</TableHead>
                      <TableHead>{t("checklist")}</TableHead>
                      <TableHead className="w-28">{t("priority")}</TableHead>
                      <TableHead className="w-40">{t("referenceCol")}</TableHead>
                      <TableHead className="w-40">{t("status")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((it) => {
                      const st = statusStyle[it.status] ?? statusStyle.not_started
                      const fromScan = typeof it.evidence_notes === "string" && it.evidence_notes.includes("Auto-sync")
                      return (
                        <TableRow key={it.id}>
                          <TableCell className="font-mono text-xs text-muted-foreground">{it.item_id}</TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <span className="font-medium">{it.title}</span>
                              {fromScan && (
                                <Badge variant="secondary" className="gap-1 text-[10px]">
                                  <Radar className="h-3 w-3" aria-hidden="true" />
                                  {t("fromScan")}
                                </Badge>
                              )}
                            </div>
                            {it.description && (
                              <p className="mt-0.5 text-xs text-muted-foreground line-clamp-1">{it.description}</p>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant={priorityVariant[it.priority] ?? "medium"}>{it.priority}</Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">{it.nis2_reference}</TableCell>
                          <TableCell>
                            <span className={cn("inline-flex items-center gap-2 text-sm font-medium", st.text)}>
                              <span className={cn("h-2 w-2 rounded-full", st.dot)} />
                              {t(st.key)}
                            </span>
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
