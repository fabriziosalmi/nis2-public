"use client"

import { CheckCircle, XCircle, AlertTriangle, Clock, Info, ShieldCheck, Loader2 } from "lucide-react"
import Link from "next/link"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useScans } from "@/hooks/use-scans"

// NIS2 Art. 21(2) subsections with Italian D.Lgs 138/2024 descriptions
const ART21_SECTIONS: Record<string, { title: string; description: string }> = {
  art21_a: { title: "Politiche di analisi dei rischi e sicurezza dei sistemi informativi", description: "Risk analysis and information system security policies" },
  art21_b: { title: "Gestione degli incidenti", description: "Incident handling procedures including detection, reporting, and response" },
  art21_c: { title: "Continuita operativa e gestione delle crisi", description: "Business continuity, backup management, and disaster recovery" },
  art21_d: { title: "Sicurezza della catena di approvvigionamento", description: "Supply chain security with direct suppliers and service providers" },
  art21_e: { title: "Sicurezza delle reti e dei sistemi informativi", description: "Security in network and information systems acquisition, development, maintenance" },
  art21_f: { title: "Gestione e divulgazione delle vulnerabilita", description: "Vulnerability handling and disclosure policies" },
  art21_g: { title: "Valutazione dell'efficacia delle misure di cybersicurezza", description: "Assessing effectiveness of cybersecurity risk-management measures" },
  art21_h: { title: "Igiene informatica e formazione", description: "Basic cyber hygiene practices and cybersecurity awareness training" },
  art21_i: { title: "Crittografia e cifratura", description: "Use of cryptography and encryption where appropriate" },
  art21_j: { title: "Sicurezza risorse umane, controllo accessi, gestione asset", description: "HR security, access control policies, and asset management" },
}

function mapStatus(matrixStatus: string): "pass" | "partial" | "fail" | "manual" {
  const s = (matrixStatus || "").toLowerCase()
  if (s.includes("automated") && !s.includes("partial")) return "pass"
  if (s.includes("partial")) return "partial"
  if (s.includes("manual")) return "manual"
  return "fail"
}

const statusConfig: Record<string, { icon: any; color: string; bg: string; label: string }> = {
  pass: { icon: CheckCircle, color: "text-green-600", bg: "bg-green-50 border-green-200", label: "Conforme" },
  partial: { icon: AlertTriangle, color: "text-yellow-600", bg: "bg-yellow-50 border-yellow-200", label: "Parziale" },
  fail: { icon: XCircle, color: "text-red-600", bg: "bg-red-50 border-red-200", label: "Non Conforme" },
  manual: { icon: Clock, color: "text-gray-500", bg: "bg-gray-50 border-gray-200", label: "Verifica Manuale" },
}

export default function CompliancePage() {
  const { data: scansData, isLoading } = useScans()

  // Find the most recent completed scan with a compliance matrix
  const latestScan = (scansData?.items || [])
    .filter((s: any) => s.status === "completed" && s.compliance_matrix)
    .sort((a: any, b: any) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0]

  const matrix = latestScan?.compliance_matrix || {}
  const hasData = Object.keys(matrix).length > 0

  // Build compliance areas from real data
  const complianceAreas = Object.entries(ART21_SECTIONS).map(([key, section]) => {
    const matrixEntry = matrix[key]
    const status = matrixEntry ? mapStatus(matrixEntry.status) : "manual"
    const detail = matrixEntry?.description || matrixEntry?.status || "Non ancora verificato"
    return { key, ...section, status, detail, automated: status === "pass" || status === "partial" }
  })

  const passCount = complianceAreas.filter((a) => a.status === "pass").length
  const failCount = complianceAreas.filter((a) => a.status === "fail").length
  const partialCount = complianceAreas.filter((a) => a.status === "partial").length
  const manualCount = complianceAreas.filter((a) => a.status === "manual").length

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Matrice di Conformita NIS2</h1>
        <p className="text-muted-foreground">
          Art. 21 D.Lgs 138/2024 — Misure di gestione dei rischi di cybersicurezza
        </p>
      </div>

      {!hasData && (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <div className="rounded-full bg-muted p-4 mb-4">
              <ShieldCheck className="h-8 w-8 text-muted-foreground" />
            </div>
            <h3 className="text-lg font-medium mb-1">Nessun dato di compliance disponibile</h3>
            <p className="text-sm text-muted-foreground mb-6 max-w-md">
              Esegui una scansione di conformita per popolare automaticamente la matrice Art. 21.
              I check automatizzati verificheranno sicurezza TLS, DNS, header HTTP, e altro.
            </p>
            <Button asChild>
              <Link href="/dashboard/scans/new">Esegui Prima Scansione</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Summary cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="flex items-center gap-3 pt-6">
            <CheckCircle className="h-8 w-8 text-green-600" />
            <div>
              <p className="text-2xl font-bold">{passCount}</p>
              <p className="text-sm text-muted-foreground">Conformi</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 pt-6">
            <AlertTriangle className="h-8 w-8 text-yellow-600" />
            <div>
              <p className="text-2xl font-bold">{partialCount}</p>
              <p className="text-sm text-muted-foreground">Parziali</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 pt-6">
            <XCircle className="h-8 w-8 text-red-600" />
            <div>
              <p className="text-2xl font-bold">{failCount}</p>
              <p className="text-sm text-muted-foreground">Non Conformi</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 pt-6">
            <Clock className="h-8 w-8 text-gray-500" />
            <div>
              <p className="text-2xl font-bold">{manualCount}</p>
              <p className="text-sm text-muted-foreground">Verifica Manuale</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {latestScan && (
        <p className="text-xs text-muted-foreground">
          Basato sulla scansione: <strong>{latestScan.name}</strong> — Score: {latestScan.total_score}/100 — {new Date(latestScan.created_at).toLocaleDateString("it-IT")}
        </p>
      )}

      {/* Compliance areas */}
      <div className="grid gap-4">
        {complianceAreas.map((area) => {
          const config = statusConfig[area.status]
          const StatusIcon = config.icon
          const letter = area.key.replace("art21_", "")

          return (
            <Card key={area.key} className={cn("border", config.bg)}>
              <CardContent className="pt-6">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-background border font-bold text-sm">
                    {letter}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 sm:gap-4">
                      <div>
                        <h3 className="font-semibold">{area.title}</h3>
                        <p className="mt-1 text-sm text-muted-foreground">{area.description}</p>
                        <p className="mt-2 text-sm italic">{area.detail}</p>
                      </div>
                      <div className="flex sm:flex-col items-center sm:items-end gap-2 shrink-0">
                        <div className={cn("flex items-center gap-1.5", config.color)}>
                          <StatusIcon className="h-5 w-5" />
                          <span className="text-sm font-semibold">{config.label}</span>
                        </div>
                        <Badge variant={area.automated ? "secondary" : "outline"} className="text-xs">
                          {area.automated ? "Automatizzato" : "Manuale"}
                        </Badge>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <Card>
        <CardContent className="flex items-start gap-3 pt-6">
          <Info className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
          <div className="text-sm text-muted-foreground">
            <p className="font-medium text-foreground">Informazioni sulla matrice</p>
            <p className="mt-1">
              Questa matrice mappa i requisiti dell'Art. 21(2) della Direttiva NIS2 (EU 2022/2555),
              recepita in Italia con D.Lgs 138/2024. I check automatizzati verificano TLS, DNS, header
              di sicurezza HTTP, crittografia, e gestione incidenti. Le voci "Verifica Manuale" richiedono
              attestazione dal team compliance.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
