// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState, Fragment } from "react"
import { Loader2, Filter, ChevronDown, ChevronRight, AlertTriangle, Download } from "lucide-react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useFindings, useUpdateFinding } from "@/hooks/use-findings"
import { useDebounce } from "@/hooks/use-debounce"
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

export default function FindingsPage() {
  const t = useTranslations("findings")
  // v2.4.23 audit a11y namespace for accessibility-only strings
  // (filter Select labels, checkbox labels, expand/collapse buttons).
  const ta = useTranslations("a11y")
  const [severityFilter, setSeverityFilter] = useState("all")
  const [statusFilter, setStatusFilter] = useState("all")
  const [categoryFilter, setCategoryFilter] = useState("all")
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [bulkStatus, setBulkStatus] = useState("")

  // v2.4.17 audit S-DRA-02: debounce filter changes before they hit
  // useFindings. Without this, a user clicking through three Select
  // dropdowns in quick succession fires three concurrent
  // /api/v1/findings requests with no arrival-order guarantee — the
  // table can end up displaying the second click's filters rather
  // than the third.
  const debouncedSeverity = useDebounce(severityFilter)
  const debouncedStatus = useDebounce(statusFilter)
  const debouncedCategory = useDebounce(categoryFilter)

  const params: Record<string, string> = {}
  if (debouncedSeverity !== "all") params.severity = debouncedSeverity
  if (debouncedStatus !== "all") params.status = debouncedStatus
  if (debouncedCategory !== "all") params.category = debouncedCategory

  const { data, isLoading } = useFindings(params)
  const updateFinding = useUpdateFinding()

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
      await Promise.all(
        selectedIds.map((id) =>
          updateFinding.mutateAsync({ id, data: { status: bulkStatus } })
        )
      )
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
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

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
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
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
              <Select value={statusFilter} onValueChange={setStatusFilter}>
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
              <Select value={categoryFilter} onValueChange={setCategoryFilter}>
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
            <div className="flex flex-col items-center justify-center py-16 text-center px-4">
              <div className="rounded-full bg-green-500/10 p-4 mb-4">
                <AlertTriangle className="h-8 w-8 text-green-600" />
              </div>
              <h3 className="text-lg font-medium mb-1">{t("noFindings")}</h3>
              <p className="text-sm text-muted-foreground max-w-sm">
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
                      className="cursor-pointer"
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
                        <Badge variant={severityVariant[finding.severity] || "info"}>
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
                      <TableCell className="font-mono text-sm">{finding.target}</TableCell>
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
                        <TableCell colSpan={8} className="bg-muted/30 p-4">
                          <div className="space-y-2">
                            <p className="text-sm font-medium">{t("fullDetails")}</p>
                            <p className="text-sm text-muted-foreground">{finding.message}</p>
                            <div className="flex gap-4 text-sm">
                              <span>
                                <strong>{t("source")}:</strong> {finding.scan_name}
                              </span>
                              <span>
                                <strong>{t("target")}:</strong> {finding.target}
                              </span>
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
        </CardContent>
      </Card>
    </div>
  )
}
