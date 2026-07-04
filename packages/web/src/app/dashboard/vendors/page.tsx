// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useTranslations } from "next-intl"
import { Network, ShieldCheck, AlertTriangle, Loader2, Boxes } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useVendors, useVendorStats } from "@/hooks/use-vendors"
import { useDocumentTitle } from "@/hooks/use-document-title"

const critVariant: Record<number, "critical" | "high" | "medium" | "low"> = {
  1: "critical", 2: "high", 3: "medium", 4: "low",
}

function StatCard({ icon, value, label, danger }: { icon: React.ReactNode; value: React.ReactNode; label: string; danger?: boolean }) {
  return (
    <Card className={danger ? "border-destructive/30" : undefined}>
      <CardContent className="flex items-center gap-4 py-5">
        <div className={`rounded-full p-3 ${danger ? "bg-destructive/10" : "bg-primary/10"}`}>{icon}</div>
        <div>
          <p className="text-2xl font-bold tabular-nums">{value}</p>
          <p className="text-sm text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export default function VendorsPage() {
  const t = useTranslations("vendors")
  useDocumentTitle(t("title"))

  const { data, isLoading } = useVendors()
  const { data: stats } = useVendorStats()
  const items: any[] = data?.items ?? []

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <Network className="h-6 w-6 text-primary" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        </div>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      {stats && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard icon={<Boxes className="h-5 w-5 text-primary" aria-hidden="true" />} value={stats.total ?? 0} label={t("total")} />
          <StatCard icon={<ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />} value={stats.art18_relevant ?? 0} label={t("art18")} />
          <StatCard icon={<AlertTriangle className="h-5 w-5 text-destructive" aria-hidden="true" />} value={stats.without_audit ?? 0} label={t("withoutAudit")} danger={(stats.without_audit ?? 0) > 0} />
          <StatCard icon={<ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />} value={stats.avg_security_score ?? "—"} label={t("avgScore")} />
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
                <Network className="h-9 w-9 text-primary opacity-80" aria-hidden="true" />
              </div>
              <h3 className="text-xl font-semibold mb-1.5">{t("noVendors")}</h3>
              <p className="text-muted-foreground max-w-md">{t("noVendorsDesc")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("colName")}</TableHead>
                  <TableHead className="w-28">{t("colCriticality")}</TableHead>
                  <TableHead>{t("colType")}</TableHead>
                  <TableHead className="w-28">{t("colAccess")}</TableHead>
                  <TableHead className="w-24">{t("colLocation")}</TableHead>
                  <TableHead className="w-24">{t("colScore")}</TableHead>
                  <TableHead className="w-32">{t("colCert")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((v) => {
                  const score = v.security_score
                  const scoreTone = score == null ? "text-muted-foreground" : score >= 70 ? "text-emerald-600 dark:text-emerald-400" : score >= 50 ? "text-amber-600 dark:text-amber-400" : "text-destructive"
                  return (
                    <TableRow key={v.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{v.name}</span>
                          {v.acn_rilevanza_art18 && <Badge variant="secondary" className="text-[10px]">Art. 18</Badge>}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={critVariant[v.criticality] ?? "medium"}>{t(`crit${v.criticality}`)}</Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{v.vendor_type}</TableCell>
                      <TableCell className="text-sm capitalize">{v.data_access_level || t("none")}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{v.geographic_location || "—"}</TableCell>
                      <TableCell className={`font-semibold tabular-nums ${scoreTone}`}>{score ?? "—"}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{v.has_security_certification || "—"}</TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
