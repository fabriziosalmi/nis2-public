// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect, useState, Fragment } from "react"
import { useRouter, usePathname, useSearchParams } from "next/navigation"
import { Loader2, Filter, ChevronDown, ChevronRight, AlertTriangle, Download, ShieldAlert, X } from "lucide-react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { CopyToClipboard } from "@/components/ui/copy-to-clipboard"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useFindings, useUpdateFinding, useBulkUpdateFindings } from "@/hooks/use-findings"
import { useDebounce } from "@/hooks/use-debounce"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"

// v2.4.5 killed the /dashboard mock data; the equivalent `sampleFindings`
// array on this page lingered until v2.4.15 as dead code (declared but
// never referenced — the route uses `useFindings` against the real API).
// Removing it here closes the audit nit so the bundle no longer ships
// fake employee emails (john@example.com / jane@example.com) to clients.

const severityVariant: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
}

const severityOptions = ["all", "critical", "high", "medium", "low", "info"]
const statusOptions = ["all", "open", "acknowledged", "resolved", "false_positive"]
const categoryOptions = ["all", "TLS", "Headers", "DNS", "Web", "Ports", "WHOIS"]

// v2.5.4 (Tier 2-C): GDPR notice banner. Findings rows can capture
// hostnames, employee email addresses (from secrets scanning), public
// IP addresses (from ports / certificate transparency lookups) and
// other identifiers — all of which are personal data under GDPR Art.
// 4(1) when they relate to an identified or identifiable person. The
// platform is a *processor* of that evidence; the deployer is the
// controller. This banner is the explicit notice that closes the
// audit gap "no in-product warning that finding evidence has GDPR
// implications". Dismissible because once internalised it adds noise.
const PII_NOTICE_KEY = "nis2-findings-pii-notice-v1"

function FindingsPiiNotice() {
  const t = useTranslations("findings")
  const [mounted, setMounted] = useState(false)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    setMounted(true)
    try {
      if (localStorage.getItem(PII_NOTICE_KEY) === "dismissed") {
        setDismissed(true)
      }
    } catch {
      /* localStorage unavailable — show every visit, acceptable */
    }
  }, [])

  const handleDismiss = () => {
    try {
      localStorage.setItem(PII_NOTICE_KEY, "dismissed")
    } catch { /* no persistence — re-shows next visit */ }
    setDismissed(true)
  }

  // SSR-empty pattern (same as LegalDisclaimerModal / OrientationCard):
  // render nothing on the server so a stale localStorage state can't
  // produce a hydration mismatch on first paint.
  if (!mounted) return null
  if (dismissed) return null

  return (
    <div
      role="note"
      className="flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 dark:bg-amber-500/10 p-4"
    >
      <ShieldAlert className="h-5 w-5 shrink-0 text-amber-600" aria-hidden="true" />
      <div className="flex-1 space-y-1 text-sm">
        <p className="font-semibold text-foreground">{t("piiNoticeTitle")}</p>
        <p className="leading-relaxed text-muted-foreground">{t("piiNoticeBody")}</p>
      </div>
      <Button
        variant="ghost"
        size="sm"
        onClick={handleDismiss}
        aria-label={t("piiNoticeDismiss")}
        className="h-8 w-8 shrink-0 p-0 text-muted-foreground hover:text-foreground"
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </Button>
    </div>
  )
}

export default function FindingsPage() {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  const t = useTranslations("findings")
  // v2.4.23 audit a11y namespace for accessibility-only strings
  // (filter Select labels, checkbox labels, expand/collapse buttons).
  const ta = useTranslations("a11y")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))

  const [severityFilter, setSeverityFilter] = useState(searchParams.get("severity") || "all")
  const [statusFilter, setStatusFilter] = useState(searchParams.get("status") || "all")
  const [categoryFilter, setCategoryFilter] = useState(searchParams.get("category") || "all")
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [bulkStatus, setBulkStatus] = useState("")
  const [page, setPage] = useState(parseInt(searchParams.get("page") || "1", 10))

  useEffect(() => {
    const params = new URLSearchParams()
    if (severityFilter !== "all") params.set("severity", severityFilter)
    if (statusFilter !== "all") params.set("status", statusFilter)
    if (categoryFilter !== "all") params.set("category", categoryFilter)
    if (page !== 1) params.set("page", page.toString())
    
    // Construct new URL string and only replace if it actually changed
    const newQueryString = params.toString()
    const currentQueryString = searchParams.toString()
    
    if (newQueryString !== currentQueryString) {
      const url = newQueryString ? `${pathname}?${newQueryString}` : pathname
      router.replace(url, { scroll: false })
    }
  }, [severityFilter, statusFilter, categoryFilter, page, pathname, router, searchParams])

  const setSeverityAndResetPage = (val: string) => { setSeverityFilter(val); setPage(1) }
  const setStatusAndResetPage = (val: string) => { setStatusFilter(val); setPage(1) }
  const setCategoryAndResetPage = (val: string) => { setCategoryFilter(val); setPage(1) }

  // v2.4.17 audit S-DRA-02: debounce filter changes before they hit
  // useFindings. Without this, a user clicking through three Select
  // dropdowns in quick succession fires three concurrent
  // /api/v1/findings requests with no arrival-order guarantee — the
  // table can end up displaying the second click's filters rather
  // than the third.
  const debouncedSeverity = useDebounce(severityFilter)
  const debouncedStatus = useDebounce(statusFilter)
  const debouncedCategory = useDebounce(categoryFilter)

  const params: Record<string, any> = { page, page_size: 20 }
  if (debouncedSeverity !== "all") params.severity = debouncedSeverity
  if (debouncedStatus !== "all") params.status = debouncedStatus
  if (debouncedCategory !== "all") params.category = debouncedCategory

  const { data, isLoading } = useFindings(params)
  const updateFinding = useUpdateFinding()
  const bulkUpdateFindings = useBulkUpdateFindings()

  const findings = data?.items || []

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]))
  }

  const toggleAll = () => {
    if (selectedIds.length === findings.length) {
      setSelectedIds([])
    } else {
      setSelectedIds(findings.map((f: any) => f.id))
    }
  }

  const handleBulkUpdate = async () => {
    if (!bulkStatus || selectedIds.length === 0) return
    try {
      await bulkUpdateFindings.mutateAsync({ findingIds: selectedIds, status: bulkStatus })
      toast.success(t("updatedCount", { count: selectedIds.length }))
      setSelectedIds([])
      setBulkStatus("")
    } catch (err: any) {
      toast.error(t("updateFailed"), { description: err.message })
    }
  }

  /**
   * v2.4.17 audit O-DRA-04: bulk-export selected findings as CSV.
   *
   * Generated client-side rather than via a new API endpoint so we
   * stay within the patch's scope and don't add a backend route
   * needing its own auth, RLS, audit-log entry. The data is already
   * loaded into TanStack Query — emitting it as CSV is just text
   * shuffling.
   *
   * Edge cases:
   *   - Empty selection: button is disabled (selectedIds.length > 0
   *     gates the bulk-action bar entirely).
   *   - Cell escaping: every value is wrapped in double quotes and
   *     internal quotes are doubled per RFC 4180. This is safe even
   *     for values containing commas, newlines, or quotes.
   *   - BOM prefix: Excel chokes on UTF-8 without a BOM and shows
   *     mojibake for accented characters; we prepend U+FEFF so
   *     "à"/"è"/"ñ" import cleanly into Excel without an extra step.
   */
  const handleBulkExport = () => {
    const rows = findings.filter((f: any) => selectedIds.includes(f.id))
    if (rows.length === 0) return

    const escape = (v: unknown): string => {
      if (v === null || v === undefined) return ""
      const s = String(v)
      // Always quote — simpler than detecting which fields need it
      // and the file size hit is irrelevant for typical exports.
      return `"${s.replace(/"/g, '""')}"`
    }

    const headers = [
      "id", "severity", "category", "status", "message",
      "target", "scan_name", "assigned_to", "created_at",
    ]
    const csv = [
      headers.join(","),
      ...rows.map((r: any) => headers.map((h) => escape(r[h])).join(",")),
    ].join("\n")

    // BOM so Excel reads UTF-8 correctly. `﻿` is the BOM
    // codepoint; prepending it inside the Blob constructor is the
    // only way to make Excel display non-ASCII characters cleanly.
    const blob = new Blob(["﻿" + csv], {
      type: "text/csv;charset=utf-8;",
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    // Filename pattern matches the reports module convention:
    // `nis2-<resource>-<yyyy-MM-dd>.csv`. Locale-agnostic ISO date
    // so re-imports sort lexicographically by run.
    const today = new Date().toISOString().slice(0, 10)
    a.download = `nis2-findings-${today}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    toast.success(t("exportedCount", { count: rows.length }))
  }

  // Severity / status enum keys map directly to translation keys in the
  // `findings` namespace; for the special "all" value we use a sibling
  // key per filter (`allSeverities`, `allStatuses`, `allCategories`).
  const severityLabel = (s: string) =>
    s === "all" ? t("allSeverities") : t(s as any)
  const statusLabel = (s: string) => {
    if (s === "all") return t("allStatuses")
    // status keys in JSON use camelCase (`falsePositive`); the API returns
    // snake_case (`false_positive`). Keep the API value for storage and
    // map at display time.
    const key = s === "false_positive" ? "falsePositive"
              : s === "in_progress" ? "inProgress"
              : s
    return t(key as any)
  }
  const categoryLabel = (s: string) =>
    s === "all" ? t("allCategories") : s

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <div className="hidden md:flex items-center gap-2">
          {/* Animated Counter for total findings, premium UX element */}
          <div className="flex flex-col items-end">
            <span className="text-sm text-muted-foreground uppercase tracking-widest font-semibold">{t("total", { defaultValue: "Total Findings" })}</span>
            <span className="text-2xl font-mono tabular-nums font-bold text-primary">{data?.total || 0}</span>
          </div>
        </div>
      </div>
      <FindingsPiiNotice />

      {/* Filters */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
            <CardTitle className="text-sm font-medium">{t("filters")}</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {/* v2.4.23 audit a11y-13 (WCAG SC 4.1.2 / 3.3.2): the
              filter Selects relied on a placeholder string for
              their label, which is invisible to screen-readers
              once a value is picked ("All severities" replaces
              "Severity" in the visual trigger). aria-label gives
              each Select a stable accessible name independent of
              its current value. */}
          <div className="flex flex-wrap gap-3">
            <div className="w-40">
              <Select value={severityFilter} onValueChange={setSeverityAndResetPage}>
                <SelectTrigger aria-label={t("severity")}>
                  <SelectValue placeholder={t("severity")} />
                </SelectTrigger>
                <SelectContent>
                  {severityOptions.map((s) => (
                    <SelectItem key={s} value={s}>{severityLabel(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="w-40">
              <Select value={statusFilter} onValueChange={setStatusAndResetPage}>
                <SelectTrigger aria-label={t("status")}>
                  <SelectValue placeholder={t("status")} />
                </SelectTrigger>
                <SelectContent>
                  {statusOptions.map((s) => (
                    <SelectItem key={s} value={s}>{statusLabel(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="w-40">
              <Select value={categoryFilter} onValueChange={setCategoryAndResetPage}>
                <SelectTrigger aria-label={t("category")}>
                  <SelectValue placeholder={t("category")} />
                </SelectTrigger>
                <SelectContent>
                  {categoryOptions.map((s) => (
                    <SelectItem key={s} value={s}>{categoryLabel(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Bulk actions */}
      {selectedIds.length > 0 && (
        <div className="flex items-center gap-3 rounded-lg border bg-muted/50 p-3">
          <span className="text-sm font-medium">{t("selectedCount", { count: selectedIds.length })}</span>
          <Select value={bulkStatus} onValueChange={setBulkStatus}>
            <SelectTrigger className="w-48" aria-label={t("setStatusPlaceholder")}>
              <SelectValue placeholder={t("setStatusPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="acknowledged">{t("acknowledged")}</SelectItem>
              <SelectItem value="resolved">{t("resolved")}</SelectItem>
              <SelectItem value="false_positive">{t("falsePositive")}</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" onClick={handleBulkUpdate} disabled={!bulkStatus || updateFinding.isPending}>
            {updateFinding.isPending && <Loader2 className="mr-2 h-3 w-3 animate-spin" aria-hidden="true" />}
            {t("apply")}
          </Button>
          {/* v2.4.17 audit O-DRA-04: bulk-export selected findings
              as CSV for sharing with teams / external tooling. */}
          <Button variant="outline" size="sm" onClick={handleBulkExport}>
            <Download className="mr-2 h-3 w-3" aria-hidden="true" />
            {t("exportCsv")}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setSelectedIds([])}>
            {t("clearSelection")}
          </Button>
        </div>
      )}

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : findings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-24 text-center px-4 relative overflow-hidden bg-card/30">
              <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(150,150,150,0.1) 1px, transparent 0)', backgroundSize: '24px 24px' }}></div>
              <div className="absolute inset-0 pointer-events-none bg-gradient-to-b from-transparent to-card/80"></div>
              
              <div className="relative z-10 rounded-full border border-primary/20 bg-primary/5 p-6 mb-6 shadow-2xl">
                <ShieldAlert className="h-10 w-10 text-primary opacity-80" />
              </div>
              <h3 className="relative z-10 text-2xl font-semibold mb-2 tracking-tight">{t("noFindings")}</h3>
              <p className="relative z-10 text-muted-foreground max-w-md">
                {severityFilter !== "all" || statusFilter !== "all" || categoryFilter !== "all"
                  ? t("noFindingsFiltered")
                  : t("noFindingsDescription")}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">
                    {/* v2.4.23 audit a11y-04 (WCAG SC 4.1.2): the
                        select-all checkbox had no label — SR users
                        heard "checkbox" with no idea what toggling
                        it would do. aria-label gives it a stable
                        name regardless of selection state. */}
                    <input
                      type="checkbox"
                      checked={selectedIds.length === findings.length && findings.length > 0}
                      onChange={toggleAll}
                      aria-label={ta("selectAllRows")}
                      className="h-4 w-4 rounded"
                    />
                  </TableHead>
                  <TableHead className="w-6">
                    <span className="sr-only">{ta("expandRow")}</span>
                  </TableHead>
                  <TableHead>{t("severity")}</TableHead>
                  <TableHead>{t("category")}</TableHead>
                  <TableHead>{t("message")}</TableHead>
                  <TableHead>{t("target")}</TableHead>
                  <TableHead>{t("status")}</TableHead>
                  <TableHead>{t("assigned")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.map((finding: any) => (
                  <Fragment key={finding.id}>
                    <TableRow
                      className="cursor-pointer group"
                      onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                    >
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        {/* v2.4.23 audit a11y-17 (WCAG SC 4.1.2):
                            per-row checkbox now names the finding it
                            selects (severity + truncated message) so
                            SR users navigating a table of 50+ rows
                            can tell which row they're toggling. */}
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(finding.id)}
                          onChange={() => toggleSelect(finding.id)}
                          aria-label={ta("selectRow", { label: finding.message?.slice(0, 60) || finding.id })}
                          className="h-4 w-4 rounded"
                        />
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        {/* v2.4.23 audit a11y-18 (WCAG SC 2.1.1
                            Keyboard / 4.1.2 Name, Role, Value): the
                            row was expandable only by clicking
                            anywhere on it — no keyboard equivalent,
                            no programmatic role, no aria-expanded
                            state. Now a real <button> in the chevron
                            cell handles the toggle for keyboard
                            users while the row-click stays for
                            mouse users (e.stopPropagation on the
                            checkbox cell prevents double-toggle). */}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation()
                            setExpandedId(expandedId === finding.id ? null : finding.id)
                          }}
                          aria-expanded={expandedId === finding.id}
                          aria-label={
                            expandedId === finding.id
                              ? ta("collapseRow")
                              : ta("expandRow")
                          }
                          className="flex items-center justify-center rounded p-0.5 hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
                        >
                          {expandedId === finding.id ? (
                            <ChevronDown className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
                          )}
                        </button>
                      </TableCell>
                      <TableCell>
                        <Badge 
                          variant={severityVariant[finding.severity?.toLowerCase() || "info"]}
                          className={cn(
                            "transition-all duration-300",
                            finding.severity?.toLowerCase() === "critical" && "animate-pulse shadow-[0_0_12px_rgba(239,68,68,0.5)] ring-1 ring-red-500/50"
                          )}
                        >
                          {/* v2.4.17 audit S-DRA-05: severity values
                              come back lowercase from the API
                              ("critical" / "high" / "medium" / "low"
                              / "info"); the `findings` namespace has
                              translated labels for each. */}
                          {t((finding.severity || "info").toLowerCase() as any)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{finding.category}</Badge>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <p className="truncate text-sm">{finding.message}</p>
                      </TableCell>
                      <TableCell className="font-mono text-sm group">
                        <div className="flex items-center gap-2">
                          <span className="truncate max-w-[150px]">{finding.target}</span>
                          <CopyToClipboard value={finding.target} className="-ml-1" />
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="secondary"
                          className={cn(
                            finding.status === "open" && "bg-red-100 text-red-800",
                            finding.status === "acknowledged" && "bg-yellow-100 text-yellow-800",
                            finding.status === "resolved" && "bg-green-100 text-green-800",
                            finding.status === "false_positive" && "bg-gray-100 text-gray-800"
                          )}
                        >
                          {/* v2.4.17 audit N-DRA-03: was rendering
                              `finding.status.replace("_", " ")` →
                              "false positive" lowercase. Map the
                              snake_case status onto the existing
                              camelCase i18n keys (open, acknowledged,
                              inProgress, resolved, falsePositive). */}
                          {t(
                            ({
                              open: "open",
                              acknowledged: "acknowledged",
                              in_progress: "inProgress",
                              resolved: "resolved",
                              false_positive: "falsePositive",
                            } as Record<string, string>)[finding.status] || finding.status
                          )}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {finding.assigned_to || "--"}
                      </TableCell>
                    </TableRow>
                    {expandedId === finding.id && (
                      <TableRow key={`${finding.id}-expanded`}>
                        <TableCell colSpan={8} className="bg-muted/10 p-0 border-b-0">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 shadow-inner bg-gradient-to-br from-card/50 to-muted/30">
                            {/* Technical Detail & Rationale */}
                            <div className="md:col-span-2 space-y-5">
                              <div>
                                <h4 className="text-xs font-bold text-primary uppercase tracking-widest mb-2 flex items-center gap-2">
                                  {t("technicalDetail", { defaultValue: "Technical Details" })}
                                </h4>
                                <div className="text-sm text-foreground/90 leading-relaxed bg-background/50 p-4 rounded-lg border border-border/50 shadow-sm font-mono whitespace-pre-wrap">
                                  {finding.technical_detail || finding.message}
                                </div>
                              </div>
                              {finding.rationale && (
                                <div>
                                  <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-widest mb-2">
                                    {t("rationale", { defaultValue: "Impact & Rationale" })}
                                  </h4>
                                  <p className="text-sm text-muted-foreground bg-background/30 p-3 rounded-lg border border-border/50">
                                    {finding.rationale}
                                  </p>
                                </div>
                              )}
                              <div className="grid grid-cols-2 gap-4 pt-2">
                                <div className="bg-background/40 p-3 rounded-lg border border-border/50">
                                  <span className="block text-xs font-medium text-muted-foreground mb-1">{t("source")}</span>
                                  <span className="text-sm font-mono">{finding.scan_name}</span>
                                </div>
                                <div className="bg-background/40 p-3 rounded-lg border border-border/50 overflow-hidden">
                                  <span className="block text-xs font-medium text-muted-foreground mb-1">{t("target")}</span>
                                  <span className="text-sm font-mono truncate block" title={finding.target}>{finding.target}</span>
                                </div>
                              </div>
                            </div>
                            
                            {/* Remediation Bento Box */}
                            <div className="space-y-4 bg-background/60 p-5 rounded-xl border border-primary/10 shadow-sm relative overflow-hidden">
                              <div className="absolute top-0 right-0 p-4 opacity-10">
                                <ShieldAlert className="w-24 h-24 text-primary" />
                              </div>
                              <h4 className="relative z-10 text-xs font-bold text-primary uppercase tracking-widest flex items-center gap-2">
                                <ShieldAlert className="w-4 h-4" /> 
                                {t("remediation", { defaultValue: "Remediation Guide" })}
                              </h4>
                              <p className="relative z-10 text-sm text-foreground/80 leading-relaxed">
                                {finding.remediation || t("noRemediationProvided", { defaultValue: "No recommended solution provided for this finding." })}
                              </p>
                              
                              {(finding.remediation_cost || finding.remediation_effort || finding.cvss_base_score) && (
                                <div className="relative z-10 flex flex-wrap gap-2 pt-4 border-t mt-4">
                                  {finding.cvss_base_score !== null && finding.cvss_base_score !== undefined && (
                                    <Badge variant="outline" className="bg-red-500/10 text-red-600 border-red-200">
                                      CVSS: {finding.cvss_base_score}
                                    </Badge>
                                  )}
                                  {finding.remediation_effort && (
                                    <Badge variant="outline" className="bg-blue-500/10 text-blue-600 border-blue-200">
                                      {t("effort", { defaultValue: "Effort" })}: {finding.remediation_effort}
                                    </Badge>
                                  )}
                                  {finding.remediation_cost && (
                                    <Badge variant="outline" className="bg-amber-500/10 text-amber-600 border-amber-200">
                                      {t("cost", { defaultValue: "Cost" })}: {finding.remediation_cost}
                                    </Badge>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          )}
          {/* Pagination Controls */}
          {!isLoading && findings.length > 0 && data && (
            <div className="flex items-center justify-between border-t px-4 py-3 bg-muted/20">
              <p className="text-sm text-muted-foreground">
                {t("showing", { defaultValue: "Showing" })} <span className="font-medium text-foreground">{(page - 1) * 20 + 1}</span> {t("to", { defaultValue: "to" })} <span className="font-medium text-foreground">{Math.min(page * 20, data.total)}</span> {t("of", { defaultValue: "of" })} <span className="font-medium text-foreground">{data.total}</span> {t("results", { defaultValue: "results" })}
              </p>
              <div className="flex space-x-2">
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => setPage(p => Math.max(1, p - 1))} 
                  disabled={page === 1}
                  className="h-8"
                >
                  {t("previous", { defaultValue: "Previous" })}
                </Button>
                <Button 
                  variant="outline" 
                  size="sm" 
                  onClick={() => setPage(p => p + 1)} 
                  disabled={page * 20 >= data.total}
                  className="h-8"
                >
                  {t("next", { defaultValue: "Next" })}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
