// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// Deep certificate analysis — Art. 21(2)(h), cryptography.
//
// POST /certificates/check has always returned the chain, key strength, CT log
// presence, OCSP status, SANs and an expiry risk band, and no screen ever
// called it. The translation keys for this page existed in all five locales,
// unused, which is a fair summary of the gap the review calls the credibility
// risk: the capability was built, translated and then left where only someone
// reading the OpenAPI schema would find it.
//
// The scanner's own TLS check answers "is it expired and does it validate".
// This answers the questions an auditor asks next — how long is the key, is the
// chain complete, is it in the CT logs, when does it expire — and it is the
// only place in the product where a certificate can be examined on demand
// rather than as a by-product of a scan.

"use client"

import { useState } from "react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { useMutation } from "@tanstack/react-query"
import { ShieldCheck, Loader2, Search, AlertTriangle, CheckCircle2 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { api } from "@/lib/api-client"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { errorMessage, cn } from "@/lib/utils"

/** The shape POST /certificates/check returns (CertificateAnalyzer.to_dict). */
interface CertificateReport {
  domain: string
  ip?: string | null
  port: number
  // The analyzer returns the X.509 name as its parsed components, not a
  // string. Rendering it directly gives "[object Object]".
  issuer?: Record<string, string> | string | null
  subject?: Record<string, string> | string | null
  fingerprint_sha256?: string | null
  validity: {
    not_after?: string | null
    days_remaining?: number | null
    is_expired?: boolean
    expiry_risk?: string
  }
  key: { type?: string | null; size?: number | null; strength?: string | null }
  chain: { length?: number | null; valid?: boolean | null }
  tls: { version?: string | null; cipher_suite?: string | null; weak_protocols?: string[] }
  ca: { type?: string | null; organization?: string | null }
  // Tri-state: true in the logs, false confirmed absent, null the lookup never
  // completed. Collapsing null into false is what made the report claim a
  // github.com certificate was in no CT log.
  ct: { logged?: boolean | null; log_count?: number | null }
  errors?: string[]
  sans?: string[]
  score?: number
  findings?: string[]
}

/** An X.509 name as the analyzer returns it: the parsed RDN components.
 *  Prefer the common name, fall back to the organisation, and only then to
 *  whatever is there — an issuer field is useless if it reads "[object
 *  Object]", which is what happens without this. */
function formatName(name: Record<string, string> | string | null | undefined): string {
  if (!name) return "—"
  if (typeof name === "string") return name
  return (
    name.commonName ||
    name.organizationName ||
    Object.values(name).join(", ") ||
    "—"
  )
}

function scoreTone(score: number): string {
  if (score >= 80) return "text-emerald-600 dark:text-emerald-400"
  if (score >= 50) return "text-amber-600 dark:text-amber-400"
  return "text-destructive"
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border px-4 py-3">
      <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn("mt-1 font-mono text-sm break-all", tone)}>{value}</p>
    </div>
  )
}

export default function CertificatesPage() {
  const t = useTranslations("certificates")
  useDocumentTitle(t("title"))

  const [domain, setDomain] = useState("")
  const [report, setReport] = useState<CertificateReport | null>(null)

  const check = useMutation({
    mutationFn: (value: string) => api.checkCertificate(value, 443),
    onSuccess: (data: CertificateReport) => setReport(data),
    onError: (err: unknown) =>
      toast.error(t("checkFailed"), { description: errorMessage(err) }),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    const value = domain.trim()
    if (value) check.mutate(value)
  }

  const v = report?.validity
  const days = v?.days_remaining ?? null
  const expiryTone =
    v?.is_expired || (days !== null && days < 15)
      ? "text-destructive"
      : days !== null && days < 30
        ? "text-amber-600 dark:text-amber-400"
        : undefined

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-primary" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        </div>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <Card>
        <CardContent className="pt-6">
          <form onSubmit={submit} method="post" className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1 space-y-2">
              <Label htmlFor="cert-domain">{t("domain")}</Label>
              <Input
                id="cert-domain"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder={t("domainPlaceholder")}
                autoComplete="off"
              />
            </div>
            <Button type="submit" disabled={check.isPending || !domain.trim()}>
              {check.isPending ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <Search className="mr-2 h-4 w-4" />
              )}
              {t("checkDomain")}
            </Button>
          </form>
          {/* The endpoint resolves and pins the target before connecting, and
              refuses private and reserved ranges — the same check asset
              creation performs. Saying so here sets the expectation before a
              refusal arrives as a bare 422. */}
          <p className="mt-3 text-xs text-muted-foreground">{t("publicOnlyNote")}</p>
        </CardContent>
      </Card>

      {!report ? null : (
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex flex-wrap items-center gap-3">
                <CardTitle className="text-base break-all">{report.domain}</CardTitle>
                {report.ip && <Badge variant="outline">{report.ip}</Badge>}
                <div className="ml-auto text-right">
                  <p className={cn("text-3xl font-bold tabular-nums", scoreTone(report.score ?? 0))}>
                    {report.score ?? 0}
                  </p>
                  <p className="text-xs text-muted-foreground">{t("score")}</p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                <Metric
                  label={t("expiry")}
                  tone={expiryTone}
                  value={
                    v?.is_expired
                      ? t("expired")
                      : days !== null
                        ? t("daysRemaining", { days })
                        : "—"
                  }
                />
                <Metric label={t("issuer")} value={formatName(report.issuer)} />
                <Metric
                  label={t("keyStrength")}
                  value={
                    report.key.type && report.key.type !== "Unknown"
                      ? [report.key.type, report.key.size, report.key.strength]
                          .filter(Boolean)
                          .join(" · ")
                      : "—"
                  }
                />
                <Metric
                  label={t("chain")}
                  value={
                    report.chain.valid === null || report.chain.valid === undefined
                      ? "—"
                      : `${report.chain.valid ? t("valid") : t("invalid")} (${report.chain.length ?? "?"})`
                  }
                  tone={report.chain.valid === false ? "text-destructive" : undefined}
                />
                <Metric
                  label={t("tlsVersion")}
                  value={report.tls.version || "—"}
                />
                <Metric
                  label={t("ctLogs")}
                  value={
                    report.ct.logged === null || report.ct.logged === undefined
                      ? t("ctUndetermined")
                      : report.ct.logged
                        ? t("ctLogged", { count: report.ct.log_count ?? 0 })
                        : t("ctNotLogged")
                  }
                />
              </div>

              {(report.sans?.length ?? 0) > 0 && (
                <div className="mt-4">
                  <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                    {t("sans")}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {report.sans!.map((san) => (
                      <Badge key={san} variant="secondary" className="font-mono text-xs">
                        {san}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {(report.errors?.length ?? 0) > 0 && (
            // A check that could not run is not a check that passed. These used
            // to be dropped on the floor, which is how an unreachable CT lookup
            // became "not present in any log".
            <Card className="border-amber-500/40">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">{t("notAssessed")}</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-1.5">
                  {report.errors!.map((e, i) => (
                    <li key={i} className="text-sm text-muted-foreground">{e}</li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">{t("findingsTitle")}</CardTitle>
            </CardHeader>
            <CardContent>
              {(report.findings?.length ?? 0) === 0 ? (
                <p className="flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
                  {t("noFindings")}
                </p>
              ) : (
                <ul className="space-y-2">
                  {report.findings!.map((f, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm">
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" aria-hidden="true" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
