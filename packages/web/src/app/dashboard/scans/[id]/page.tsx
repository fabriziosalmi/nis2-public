// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/messages
"use client"

import { use } from "react"
import Link from "next/link"
import { ArrowLeft, Loader2, Clock, CheckCircle, AlertTriangle, GitCompareArrows, Radar } from "lucide-react"
import { useFormatDate } from "@/lib/dates"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useScan, useScanResults, useScanFindings } from "@/hooks/use-scans"
import { cn } from "@/lib/utils"

const severityVariant: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low",
  critical: "critical", high: "high", medium: "medium", low: "low", info: "info",
}

function ComplianceStatus({ status }: { status: string }) {
  // Status labels live in the `compliancePage` namespace — same enum
  // (compliant / partial / nonCompliant / manualReview) the matrix
  // page already uses. v2.4.15 i18n cleanup.
  const tc = useTranslations("compliancePage")
  const s = (status || "").toLowerCase()
  let config = { icon: Clock, color: "text-muted-foreground", label: tc("manual") }
  if (s.includes("automated") && !s.includes("partial")) {
    config = { icon: CheckCircle, color: "text-green-600", label: tc("compliant") }
  } else if (s.includes("partial")) {
    config = { icon: AlertTriangle, color: "text-yellow-600", label: tc("partial") }
  } else if (s.includes("manual")) {
    config = { icon: Clock, color: "text-muted-foreground", label: tc("manual") }
  }
  return (
    <div className={cn("flex items-center gap-1.5", config.color)}>
      <config.icon className="h-4 w-4" />
      <span className="text-sm font-medium">{config.label}</span>
    </div>
  )
}

// v2.4.15 audit B-DRA-06: this page used to ship hardcoded ITALIAN
// ("Scansione non trovata", "Riepilogo Esecutivo", "Host analizzati"
// etc.) mixed in with the otherwise-English UI — a leftover from the
// initial Italian prototype that survived the i18n round 1 sweep.
// All user-facing strings now route through the `scanDetailsPage`
// namespace so the page localises correctly across all 5 locales.
export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const t = useTranslations("scanDetailsPage")
  const ts = useTranslations("scans")
  const tf = useTranslations("findings")
  const formatDate = useFormatDate()
  const { id } = use(params)
  const { data: scan, isLoading } = useScan(id)
  const { data: resultsData } = useScanResults(id)
  const { data: findingsData } = useScanFindings(id)

  const results = resultsData?.items || []
  const findings = findingsData?.items || []

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Radar className="h-10 w-10 text-muted-foreground mb-4" />
        <h3 className="text-lg font-medium">{t("notFoundTitle")}</h3>
        <p className="text-sm text-muted-foreground mt-1 mb-4">{t("notFoundDescription")}</p>
        <Button variant="outline" asChild><Link href="/dashboard/scans">{t("backToScans")}</Link></Button>
      </div>
    )
  }

  const score = scan.total_score
  const totalFindings = (scan.findings_critical || 0) + (scan.findings_high || 0) + (scan.findings_medium || 0) + (scan.findings_low || 0)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
        <Button variant="ghost" size="icon" asChild>
          <Link href="/dashboard/scans"><ArrowLeft className="h-4 w-4" /></Link>
        </Button>
        <div className="flex-1">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-3xl font-bold tracking-tight">{scan.name}</h1>
            <Badge variant="outline" className={cn(
              scan.status === "completed" && "border-green-500 text-green-600 bg-green-50",
              scan.status === "running" && "border-blue-500 text-blue-600 animate-pulse",
              scan.status === "failed" && "border-red-500 text-red-600",
              scan.status === "pending" && "border-yellow-500 text-yellow-600",
            )}>{ts(scan.status as any)}</Badge>
            {scan.status === "completed" && (
              <Button variant="outline" size="sm" asChild>
                <Link href={`/dashboard/scans/${id}/compare`}>
                  <GitCompareArrows className="mr-2 h-4 w-4" />{t("compare")}
                </Link>
              </Button>
            )}
          </div>
          <p className="text-muted-foreground">
            {scan.created_at && formatDate(scan.created_at, "Pp")}
            {scan.duration_seconds && ` — ${t("duration", { seconds: scan.duration_seconds })}`}
          </p>
        </div>
        {/* v2.4.23 audit a11y-05: aria-label surfaces the band so
            the score's colour-coding is supplemented by text. */}
        {score !== null && score !== undefined && (
          <div className="text-center px-4">
            <div
              className={cn("text-4xl font-bold", score > 80 ? "text-green-600" : score > 60 ? "text-yellow-600" : "text-red-600")}
              aria-label={`${score} (${score > 80 ? "good" : score > 60 ? "fair" : "poor"})`}
            >{score}</div>
            <p className="text-xs text-muted-foreground">{t("score")}</p>
          </div>
        )}
      </div>

      {/* Stats row */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-5">
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold">{scan.hosts_scanned || 0}</p><p className="text-xs text-muted-foreground">{t("hostsScanned")}</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold">{scan.hosts_alive || 0}</p><p className="text-xs text-muted-foreground">{t("hostsAlive")}</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold text-red-600">{scan.findings_critical || 0}</p><p className="text-xs text-muted-foreground">{tf("critical")}</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold text-orange-600">{scan.findings_high || 0}</p><p className="text-xs text-muted-foreground">{tf("high")}</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold text-yellow-600">{(scan.findings_medium || 0) + (scan.findings_low || 0)}</p><p className="text-xs text-muted-foreground">{t("mediumLow")}</p></CardContent></Card>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">{t("tabOverview")}</TabsTrigger>
          <TabsTrigger value="results">{t("tabResults", { count: results.length })}</TabsTrigger>
          <TabsTrigger value="findings">{t("tabFindings", { count: findings.length || totalFindings })}</TabsTrigger>
        </TabsList>

        {/* Overview tab */}
        <TabsContent value="overview" className="space-y-4">
          {scan.executive_summary && (
            <Card>
              <CardHeader><CardTitle>{t("executiveSummary")}</CardTitle></CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground leading-relaxed">{scan.executive_summary}</p>
              </CardContent>
            </Card>
          )}

          {/* Compliance Matrix from real scan data */}
          {scan.compliance_matrix && Object.keys(scan.compliance_matrix).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>{t("complianceMatrixTitle")}</CardTitle>
                <CardDescription>{t("complianceMatrixDescription")}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-3">
                  {Object.entries(scan.compliance_matrix).map(([key, item]: [string, any]) => (
                    <div key={key} className="flex items-center justify-between rounded-lg border p-3">
                      <div className="flex items-center gap-3">
                        <span className="flex h-7 w-7 items-center justify-center rounded-md bg-muted text-xs font-bold">
                          {key.replace("art21_", "")}
                        </span>
                        <p className="text-sm font-medium">{item.description || item.title || key}</p>
                      </div>
                      <ComplianceStatus status={item.status} />
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Results tab */}
        <TabsContent value="results">
          <Card>
            <CardHeader>
              <CardTitle>{t("resultsTitle")}</CardTitle>
              <CardDescription>{t("resultsDescription")}</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              {results.length === 0 ? (
                <div className="py-12 text-center text-muted-foreground text-sm">
                  {scan.status === "completed" ? t("noResults") : t("resultsPending")}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{t("target")}</TableHead>
                      <TableHead>{t("ip")}</TableHead>
                      <TableHead>{t("hostState")}</TableHead>
                      <TableHead>{t("openPorts")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {results.map((result: any) => (
                      <TableRow key={result.id}>
                        <TableCell className="font-medium">{result.target}</TableCell>
                        <TableCell className="font-mono text-sm">{result.ip}</TableCell>
                        <TableCell>
                          <Badge variant={result.is_alive ? "secondary" : "outline"} className={result.is_alive ? "bg-green-100 text-green-800" : ""}>
                            {result.is_alive ? t("hostAlive") : t("hostDead")}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {(result.open_ports || []).join(", ") || t("noPorts")}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Findings tab */}
        <TabsContent value="findings">
          <Card>
            <CardHeader>
              <CardTitle>{t("findingsTitle")}</CardTitle>
              <CardDescription>{t("findingsDescription")}</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              {findings.length === 0 ? (
                <div className="py-12 text-center text-muted-foreground text-sm">
                  {scan.status === "completed" ? t("noFindings") : t("findingsPending")}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>{tf("severity")}</TableHead>
                      <TableHead>{tf("category")}</TableHead>
                      <TableHead>{tf("message")}</TableHead>
                      <TableHead>{tf("target")}</TableHead>
                      <TableHead>{tf("remediation")}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map((finding: any) => (
                      <TableRow key={finding.id}>
                        <TableCell>
                          <Badge variant={severityVariant[finding.severity] || "secondary"}>
                            {tf((finding.severity || "").toLowerCase() as any)}
                          </Badge>
                        </TableCell>
                        <TableCell><Badge variant="outline">{finding.category}</Badge></TableCell>
                        <TableCell className="max-w-sm"><p className="text-sm">{finding.message}</p></TableCell>
                        <TableCell className="font-mono text-sm">{finding.target}</TableCell>
                        <TableCell className="max-w-xs"><p className="text-xs text-muted-foreground">{finding.remediation || "--"}</p></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
