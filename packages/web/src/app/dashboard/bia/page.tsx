// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useTranslations } from "next-intl"
import { Activity, ShieldCheck, LifeBuoy, Loader2 } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useBia } from "@/hooks/use-bia"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

const critVariant: Record<number, "critical" | "high" | "medium" | "low"> = {
  1: "critical", 2: "high", 3: "medium", 4: "low", 5: "low",
}

function StatCard({ icon, value, label }: { icon: React.ReactNode; value: React.ReactNode; label: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 py-5">
        <div className="rounded-full bg-primary/10 p-3">{icon}</div>
        <div>
          <p className="text-2xl font-bold tabular-nums">{value}</p>
          <p className="text-sm text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export default function BiaPage() {
  const t = useTranslations("bia")
  useDocumentTitle(t("title"))

  const { data, isLoading } = useBia()
  const items: any[] = data?.items ?? []
  const essential = items.filter((p) => p.acn_servizio_essenziale).length
  const withPlans = items.filter((p) => p.has_bcp && p.has_drp).length
  const h = (v: number | null | undefined) => (v == null ? "—" : `${v}${t("hours")}`)

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <Activity className="h-6 w-6 text-primary" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        </div>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      {items.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-3 lg:max-w-2xl">
          <StatCard icon={<Activity className="h-5 w-5 text-primary" aria-hidden="true" />} value={items.length} label={t("totalProcesses")} />
          <StatCard icon={<ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />} value={essential} label={t("essentialCount")} />
          <StatCard icon={<LifeBuoy className="h-5 w-5 text-primary" aria-hidden="true" />} value={withPlans} label={t("withPlans")} />
        </div>
      )}

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : items.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center px-4">
              <div className="rounded-full border border-primary/20 bg-primary/5 p-6 mb-5">
                <Activity className="h-9 w-9 text-primary opacity-80" aria-hidden="true" />
              </div>
              <h3 className="text-xl font-semibold mb-1.5">{t("noProcesses")}</h3>
              <p className="text-muted-foreground max-w-md">{t("noProcessesDesc")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("colProcess")}</TableHead>
                  <TableHead className="w-28">{t("colCriticality")}</TableHead>
                  <TableHead className="w-40">{t("colOwner")}</TableHead>
                  <TableHead className="w-20 text-right">{t("colRto")}</TableHead>
                  <TableHead className="w-20 text-right">{t("colRpo")}</TableHead>
                  <TableHead className="w-20 text-right">{t("colMtpd")}</TableHead>
                  <TableHead className="w-32">{t("colContinuity")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{p.name}</span>
                        {p.acn_servizio_essenziale && <Badge variant="secondary" className="text-[10px]">{t("essential")}</Badge>}
                      </div>
                      {p.department && <p className="text-xs text-muted-foreground">{p.department}</p>}
                    </TableCell>
                    <TableCell>
                      <Badge variant={critVariant[p.criticality_level] ?? "medium"}>{t(`crit${p.criticality_level}`)}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{p.process_owner || "—"}</TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums">{h(p.rto_hours)}</TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums">{h(p.rpo_hours)}</TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums">{h(p.mtpd_hours)}</TableCell>
                    <TableCell>
                      <div className="flex gap-1.5">
                        <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold", p.has_bcp ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : "bg-muted text-muted-foreground line-through")}>{t("bcp")}</span>
                        <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold", p.has_drp ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : "bg-muted text-muted-foreground line-through")}>{t("drp")}</span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
