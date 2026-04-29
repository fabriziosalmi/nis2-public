// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { useParams } from "next/navigation"
import { toast } from "sonner"
import {
  Minus, TrendingUp, TrendingDown,
  AlertTriangle, CheckCircle2, Shield,
} from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api } from "@/lib/api-client"
import { useScans } from "@/hooks/use-scans"
import { useDocumentTitle } from "@/hooks/use-document-title"

const severityColors: Record<string, string> = {
  CRITICAL: "destructive",
  HIGH: "destructive",
  MEDIUM: "secondary",
  LOW: "outline",
}

// v2.4.15 audit B-DRA-05: this page used to ship every label, button
// and toast in hardcoded English. Wired up to the new
// `scansComparePage` namespace so EN/IT/FR/DE/ES users see the same
// compare view in their language.
export default function ScanComparePage() {
  const t = useTranslations("scansComparePage")
  const tf = useTranslations("findings")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const params = useParams()
  const scanId = params.id as string
  const { data: scansData } = useScans()
  const [otherId, setOtherId] = useState<string>("")
  const [comparison, setComparison] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const completedScans = (scansData?.items || []).filter(
    (s: any) => s.status === "completed" && s.id !== scanId
  )

  const compare = async () => {
    if (!otherId) return
    setLoading(true)
    try {
      const data = await api.compareScan(scanId, otherId)
      setComparison(data)
    } catch (err: any) {
      toast.error(t("comparisonFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t("selectScanTitle")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <select
            value={otherId}
            onChange={(e) => setOtherId(e.target.value)}
            className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <option value="">
              {completedScans.length === 0
                ? t("noOtherScans")
                : t("selectScanPlaceholder")}
            </option>
            {completedScans.map((s: any) => (
              <option key={s.id} value={s.id}>
                {t("scanOption", {
                  name: s.name,
                  score: s.total_score ?? "--",
                  date: new Date(s.created_at).toLocaleDateString(),
                })}
              </option>
            ))}
          </select>
          <Button onClick={compare} disabled={!otherId || loading}>
            {loading ? t("comparing") : t("compare")}
          </Button>
        </CardContent>
      </Card>

      {comparison && (
        <>
          {/* Score comparison */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardContent className="pt-6 text-center">
                <p className="text-sm text-muted-foreground mb-1">{t("currentScan")}</p>
                <p className="text-3xl font-bold">{comparison.scan_a.score ?? "--"}</p>
                <p className="text-xs text-muted-foreground mt-1">{comparison.scan_a.name}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6 text-center">
                <p className="text-sm text-muted-foreground mb-1">{t("scoreDelta")}</p>
                <div className="flex items-center justify-center gap-2">
                  {comparison.score_delta > 0 ? (
                    <TrendingUp className="h-6 w-6 text-green-600" />
                  ) : comparison.score_delta < 0 ? (
                    <TrendingDown className="h-6 w-6 text-red-600" />
                  ) : (
                    <Minus className="h-6 w-6 text-muted-foreground" />
                  )}
                  <p className={`text-3xl font-bold ${
                    comparison.score_delta > 0 ? "text-green-600" : comparison.score_delta < 0 ? "text-red-600" : ""
                  }`}>
                    {comparison.score_delta > 0 ? "+" : ""}{comparison.score_delta}
                  </p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6 text-center">
                <p className="text-sm text-muted-foreground mb-1">{t("previousScan")}</p>
                <p className="text-3xl font-bold">{comparison.scan_b.score ?? "--"}</p>
                <p className="text-xs text-muted-foreground mt-1">{comparison.scan_b.name}</p>
              </CardContent>
            </Card>
          </div>

          {/* Summary stats */}
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardContent className="pt-6 flex items-center gap-3">
                <div className="rounded-lg bg-red-500/10 p-2">
                  <AlertTriangle className="h-5 w-5 text-red-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{comparison.summary.new}</p>
                  <p className="text-sm text-muted-foreground">{t("newFindings")}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6 flex items-center gap-3">
                <div className="rounded-lg bg-green-500/10 p-2">
                  <CheckCircle2 className="h-5 w-5 text-green-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{comparison.summary.resolved}</p>
                  <p className="text-sm text-muted-foreground">{t("resolved")}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6 flex items-center gap-3">
                <div className="rounded-lg bg-muted p-2">
                  <Shield className="h-5 w-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-2xl font-bold">{comparison.summary.persistent}</p>
                  <p className="text-sm text-muted-foreground">{t("persistent")}</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* New findings */}
          {comparison.new_findings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-red-600 flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5" />
                  {t("newFindingsCount", { count: comparison.new_findings.length })}
                </CardTitle>
                <CardDescription>{t("newFindingsDescription")}</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{tf("severity")}</TableHead>
                      <TableHead>{tf("category")}</TableHead>
                      <TableHead>{tf("message")}</TableHead>
                      <TableHead>{tf("target")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {comparison.new_findings.map((f: any, i: number) => (
                      <TableRow key={i}>
                        <TableCell>
                          <Badge variant={severityColors[f.severity] as any || "secondary"}>
                            {tf((f.severity || "").toLowerCase() as any)}
                          </Badge>
                        </TableCell>
                        <TableCell>{f.category}</TableCell>
                        <TableCell>{f.message}</TableCell>
                        <TableCell><code className="text-xs">{f.target}</code></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}

          {/* Resolved findings */}
          {comparison.resolved_findings.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="text-green-600 flex items-center gap-2">
                  <CheckCircle2 className="h-5 w-5" />
                  {t("resolvedFindingsCount", { count: comparison.resolved_findings.length })}
                </CardTitle>
                <CardDescription>{t("resolvedFindingsDescription")}</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{tf("severity")}</TableHead>
                      <TableHead>{tf("category")}</TableHead>
                      <TableHead>{tf("message")}</TableHead>
                      <TableHead>{tf("target")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {comparison.resolved_findings.map((f: any, i: number) => (
                      <TableRow key={i}>
                        <TableCell>
                          <Badge variant="outline" className="line-through opacity-60">
                            {tf((f.severity || "").toLowerCase() as any)}
                          </Badge>
                        </TableCell>
                        <TableCell className="opacity-60">{f.category}</TableCell>
                        <TableCell className="opacity-60">{f.message}</TableCell>
                        <TableCell className="opacity-60"><code className="text-xs">{f.target}</code></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
