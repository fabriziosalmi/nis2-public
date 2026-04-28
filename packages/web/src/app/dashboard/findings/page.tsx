// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState, Fragment } from "react"
import { Loader2, Filter, ChevronDown, ChevronRight, AlertTriangle } from "lucide-react"
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
import { cn } from "@/lib/utils"

const sampleFindings = [
  { id: "f1", severity: "critical", category: "TLS", message: "TLS 1.1 detected - deprecated and insecure protocol version. Should upgrade to TLS 1.2 or higher.", target: "legacy.example.com", status: "open", assigned_to: null, scan_name: "Production Scan" },
  { id: "f2", severity: "critical", category: "Ports", message: "Unencrypted FTP (port 21) exposed to the internet", target: "files.example.com", status: "open", assigned_to: "john@example.com", scan_name: "Production Scan" },
  { id: "f3", severity: "high", category: "Headers", message: "Missing Content-Security-Policy header allows potential XSS attacks", target: "api.example.com", status: "open", assigned_to: null, scan_name: "API Scan" },
  { id: "f4", severity: "high", category: "Headers", message: "Missing X-Frame-Options header allows clickjacking", target: "legacy.example.com", status: "acknowledged", assigned_to: "jane@example.com", scan_name: "Production Scan" },
  { id: "f5", severity: "high", category: "DNS", message: "SPF record too permissive - allows unauthorized senders", target: "example.com", status: "open", assigned_to: null, scan_name: "DNS Audit" },
  { id: "f6", severity: "medium", category: "DNS", message: "DNSSEC not configured for the domain", target: "example.com", status: "open", assigned_to: null, scan_name: "DNS Audit" },
  { id: "f7", severity: "medium", category: "TLS", message: "Weak cipher suite enabled: TLS_RSA_WITH_AES_128_CBC_SHA", target: "api.example.com", status: "acknowledged", assigned_to: "john@example.com", scan_name: "API Scan" },
  { id: "f8", severity: "medium", category: "Web", message: "Missing Strict-Transport-Security header", target: "staging.example.com", status: "resolved", assigned_to: null, scan_name: "Staging Scan" },
  { id: "f9", severity: "low", category: "Headers", message: "Missing X-Content-Type-Options header", target: "cdn.example.com", status: "open", assigned_to: null, scan_name: "CDN Scan" },
  { id: "f10", severity: "low", category: "WHOIS", message: "Domain expires within 90 days", target: "example.com", status: "open", assigned_to: null, scan_name: "DNS Audit" },
  { id: "f11", severity: "info", category: "DNS", message: "Multiple A records detected (load balancing)", target: "api.example.com", status: "open", assigned_to: null, scan_name: "API Scan" },
  { id: "f12", severity: "info", category: "Web", message: "Server header exposes technology stack", target: "prod.example.com", status: "false_positive", assigned_to: null, scan_name: "Production Scan" },
]

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
  const [severityFilter, setSeverityFilter] = useState("all")
  const [statusFilter, setStatusFilter] = useState("all")
  const [categoryFilter, setCategoryFilter] = useState("all")
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [bulkStatus, setBulkStatus] = useState("")

  const params: Record<string, string> = {}
  if (severityFilter !== "all") params.severity = severityFilter
  if (statusFilter !== "all") params.status = statusFilter
  if (categoryFilter !== "all") params.category = categoryFilter

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
            <Filter className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">{t("filters")}</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-3">
            <div className="w-40">
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger>
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
                <SelectTrigger>
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
                <SelectTrigger>
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
            <SelectTrigger className="w-48">
              <SelectValue placeholder={t("setStatusPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="acknowledged">{t("acknowledged")}</SelectItem>
              <SelectItem value="resolved">{t("resolved")}</SelectItem>
              <SelectItem value="false_positive">{t("falsePositive")}</SelectItem>
            </SelectContent>
          </Select>
          <Button size="sm" onClick={handleBulkUpdate} disabled={!bulkStatus || updateFinding.isPending}>
            {updateFinding.isPending && <Loader2 className="mr-2 h-3 w-3 animate-spin" />}
            {t("apply")}
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
                    <input
                      type="checkbox"
                      checked={selectedIds.length === findings.length && findings.length > 0}
                      onChange={toggleAll}
                      className="h-4 w-4 rounded"
                    />
                  </TableHead>
                  <TableHead className="w-6"></TableHead>
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
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(finding.id)}
                          onChange={() => toggleSelect(finding.id)}
                          className="h-4 w-4 rounded"
                        />
                      </TableCell>
                      <TableCell>
                        {expandedId === finding.id ? (
                          <ChevronDown className="h-4 w-4 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={severityVariant[finding.severity] || "info"}>
                          {finding.severity}
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
                          {finding.status.replace("_", " ")}
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
