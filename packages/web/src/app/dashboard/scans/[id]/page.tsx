// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { use } from "react"
import Link from "next/link"
import { ArrowLeft, Loader2, Clock, CheckCircle, XCircle, AlertTriangle, GitCompareArrows, Radar } from "lucide-react"
import { format } from "date-fns"
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
  const s = (status || "").toLowerCase()
  let config = { icon: Clock, color: "text-muted-foreground", label: "Manuale" }
  if (s.includes("automated") && !s.includes("partial")) config = { icon: CheckCircle, color: "text-green-600", label: "Conforme" }
  else if (s.includes("partial")) config = { icon: AlertTriangle, color: "text-yellow-600", label: "Parziale" }
  else if (s.includes("manual")) config = { icon: Clock, color: "text-muted-foreground", label: "Manuale" }
  return (
    <div className={cn("flex items-center gap-1.5", config.color)}>
      <config.icon className="h-4 w-4" />
      <span className="text-sm font-medium">{config.label}</span>
    </div>
  )
}

export default function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
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
        <h3 className="text-lg font-medium">Scansione non trovata</h3>
        <p className="text-sm text-muted-foreground mt-1 mb-4">La scansione richiesta non esiste o non hai i permessi.</p>
        <Button variant="outline" asChild><Link href="/dashboard/scans">Torna alle scansioni</Link></Button>
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
            )}>{scan.status}</Badge>
            {scan.status === "completed" && (
              <Button variant="outline" size="sm" asChild>
                <Link href={`/dashboard/scans/${id}/compare`}>
                  <GitCompareArrows className="mr-2 h-4 w-4" />Compara
                </Link>
              </Button>
            )}
          </div>
          <p className="text-muted-foreground">
            {scan.created_at && format(new Date(scan.created_at), "d MMM yyyy 'alle' HH:mm")}
            {scan.duration_seconds && ` — Durata: ${scan.duration_seconds}s`}
          </p>
        </div>
        {score !== null && score !== undefined && (
          <div className="text-center px-4">
            <div className={cn("text-4xl font-bold", score > 80 ? "text-green-600" : score > 60 ? "text-yellow-600" : "text-red-600")}>{score}</div>
            <p className="text-xs text-muted-foreground">Score</p>
          </div>
        )}
      </div>

      {/* Stats row */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-5">
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold">{scan.hosts_scanned || 0}</p><p className="text-xs text-muted-foreground">Host analizzati</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold">{scan.hosts_alive || 0}</p><p className="text-xs text-muted-foreground">Host attivi</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold text-red-600">{scan.findings_critical || 0}</p><p className="text-xs text-muted-foreground">Critici</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold text-orange-600">{scan.findings_high || 0}</p><p className="text-xs text-muted-foreground">Alti</p></CardContent></Card>
        <Card><CardContent className="pt-4 text-center"><p className="text-2xl font-bold text-yellow-600">{(scan.findings_medium || 0) + (scan.findings_low || 0)}</p><p className="text-xs text-muted-foreground">Medi+Bassi</p></CardContent></Card>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList>
          <TabsTrigger value="overview">Panoramica</TabsTrigger>
          <TabsTrigger value="results">Risultati ({results.length})</TabsTrigger>
          <TabsTrigger value="findings">Findings ({findings.length || totalFindings})</TabsTrigger>
        </TabsList>

        {/* Overview tab */}
        <TabsContent value="overview" className="space-y-4">
          {scan.executive_summary && (
            <Card>
              <CardHeader><CardTitle>Riepilogo Esecutivo</CardTitle></CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground leading-relaxed">{scan.executive_summary}</p>
              </CardContent>
            </Card>
          )}

          {/* Compliance Matrix from real scan data */}
          {scan.compliance_matrix && Object.keys(scan.compliance_matrix).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Matrice Conformita NIS2 Art. 21</CardTitle>
                <CardDescription>Stato di ogni area basato sui check automatici</CardDescription>
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
              <CardTitle>Risultati per Host</CardTitle>
              <CardDescription>Dettaglio scansione per ogni target analizzato</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              {results.length === 0 ? (
                <div className="py-12 text-center text-muted-foreground text-sm">
                  {scan.status === "completed" ? "Nessun risultato disponibile per questa scansione." : "I risultati appariranno al completamento della scansione."}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Target</TableHead>
                      <TableHead>IP</TableHead>
                      <TableHead>Stato</TableHead>
                      <TableHead>Porte Aperte</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {results.map((result: any) => (
                      <TableRow key={result.id}>
                        <TableCell className="font-medium">{result.target}</TableCell>
                        <TableCell className="font-mono text-sm">{result.ip}</TableCell>
                        <TableCell>
                          <Badge variant={result.is_alive ? "secondary" : "outline"} className={result.is_alive ? "bg-green-100 text-green-800" : ""}>
                            {result.is_alive ? "Attivo" : "Inattivo"}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {(result.open_ports || []).join(", ") || "Nessuna"}
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
              <CardTitle>Findings</CardTitle>
              <CardDescription>Problemi di sicurezza rilevati durante la scansione</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              {findings.length === 0 ? (
                <div className="py-12 text-center text-muted-foreground text-sm">
                  {scan.status === "completed" ? "Nessun finding rilevato — ottimo risultato!" : "I findings appariranno al completamento della scansione."}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severita</TableHead>
                      <TableHead>Categoria</TableHead>
                      <TableHead>Descrizione</TableHead>
                      <TableHead>Target</TableHead>
                      <TableHead>Rimedio</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map((finding: any) => (
                      <TableRow key={finding.id}>
                        <TableCell>
                          <Badge variant={severityVariant[finding.severity] || "secondary"}>
                            {finding.severity}
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
