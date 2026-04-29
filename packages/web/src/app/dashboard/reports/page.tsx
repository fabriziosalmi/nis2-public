// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import Link from "next/link"
import { Download, FileText, Loader2, Radar } from "lucide-react"
import { useFormatDate } from "@/lib/dates"
import { toast } from "sonner"
import { useTranslations } from "next-intl"

import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import { useScans } from "@/hooks/use-scans"
import { api } from "@/lib/api-client"
import { cn } from "@/lib/utils"

// Format keys map to entries under `reports.formatHints` in messages/*.json.
// Labels (PDF, HTML, ...) stay as-is — they're proper nouns, not localised.
const FORMATS = [
  { value: "pdf",      label: "PDF" },
  { value: "html",     label: "HTML" },
  { value: "markdown", label: "Markdown" },
  { value: "json",     label: "JSON" },
  { value: "csv",      label: "CSV" },
  { value: "junit",    label: "JUnit XML" },
] as const

type FormatValue = typeof FORMATS[number]["value"]

// Per-row state: which format is selected, and the in-flight task id /
// lifecycle phase. Kept as a single Map keyed by scan id so multiple rows
// can be generating simultaneously without state-sharing bugs.
type RowState = {
  format: FormatValue
  phase: "idle" | "queued" | "polling" | "ready" | "error"
  taskId?: string
  error?: string
}

const POLL_MS = 1500
const POLL_TIMEOUT_MS = 5 * 60 * 1000  // 5 minutes — beyond this, surface an error

export default function ReportsPage() {
  const t = useTranslations("reports")
  // Re-use the `scans` namespace's pagination strings (previous /
  // page / next) — same widget renders on both pages, no need to
  // mint separate keys.
  const ts = useTranslations("scans")
  const formatDate = useFormatDate()
  const [page, setPage] = useState(1)
  const { data, isLoading } = useScans(page)
  const [rowState, setRowState] = useState<Record<string, RowState>>({})

  const scans = data?.items || []
  // Reports are only generatable from completed scans (the API enforces it
  // with a 400 — we filter client-side too so the UI doesn't hand the user
  // a button that always errors).
  const completed = scans.filter((s: any) => s.status === "completed")

  const setRow = (scanId: string, patch: Partial<RowState>) =>
    setRowState((prev) => ({
      ...prev,
      [scanId]: { format: "pdf", phase: "idle", ...prev[scanId], ...patch },
    }))

  const handleGenerate = async (scanId: string, fmt: FormatValue) => {
    setRow(scanId, { phase: "queued", format: fmt, error: undefined })
    try {
      const { task_id } = await api.generateReport(scanId, fmt)
      setRow(scanId, { phase: "polling", taskId: task_id })
      // Poll status. The Celery task writes the file to disk and returns a
      // path/filename via the task result; download is a separate endpoint.
      const startedAt = Date.now()
      const tick = async () => {
        const status = await api.getReportStatus(task_id)
        if (status.status === "success") {
          setRow(scanId, { phase: "ready" })
          toast.success(t("ready", { format: fmt.toUpperCase() }), {
            description: t("readyDescription"),
          })
          return
        }
        if (status.status === "failure") {
          setRow(scanId, { phase: "error", error: status.error || "Generation failed" })
          toast.error(t("generationFailed"), { description: status.error })
          return
        }
        if (Date.now() - startedAt > POLL_TIMEOUT_MS) {
          setRow(scanId, { phase: "error", error: "Timed out after 5 minutes" })
          toast.error(t("timeout"), { description: t("timeoutDescription") })
          return
        }
        setTimeout(tick, POLL_MS)
      }
      tick()
    } catch (err: any) {
      setRow(scanId, { phase: "error", error: err.message })
      toast.error(t("queueFailed"), { description: err.message })
    }
  }

  const handleDownload = (scanId: string) => {
    const state = rowState[scanId]
    if (!state?.taskId) return
    // The download endpoint streams a FileResponse with the right
    // Content-Disposition; opening it in a new tab triggers the browser's
    // native save dialog without us having to fetch + blob + revoke.
    window.open(api.getReportDownloadUrl(state.taskId), "_blank")
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : completed.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center px-4">
              <div className="rounded-full bg-muted p-4 mb-4">
                <FileText className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-medium mb-1">{t("noCompletedScans")}</h3>
              <p className="text-sm text-muted-foreground mb-6 max-w-sm">
                {t("noCompletedScansDescription")}
              </p>
              <Button asChild>
                <Link href="/dashboard/scans/new">
                  <Radar className="mr-2 h-4 w-4" />
                  {t("newScan")}
                </Link>
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("scan")}</TableHead>
                  <TableHead>{t("score")}</TableHead>
                  <TableHead>{t("findings")}</TableHead>
                  <TableHead>{t("completed")}</TableHead>
                  <TableHead className="w-[200px]">{t("format")}</TableHead>
                  <TableHead className="text-right w-[200px]">{t("action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {completed.map((scan: any) => {
                  const state = rowState[scan.id] || { format: "pdf", phase: "idle" }
                  const totalFindings =
                    (scan.findings_critical || 0) +
                    (scan.findings_high || 0) +
                    (scan.findings_medium || 0) +
                    (scan.findings_low || 0)
                  const busy = state.phase === "queued" || state.phase === "polling"

                  return (
                    <TableRow key={scan.id}>
                      <TableCell className="font-medium">
                        <Link
                          href={`/dashboard/scans/${scan.id}`}
                          className="hover:underline"
                        >
                          {scan.name}
                        </Link>
                      </TableCell>
                      <TableCell>
                        {/* v2.4.23 audit a11y-05: aria-label surfaces
                            the band so the colour isn't the only
                            signal of "is this a good or bad score". */}
                        {scan.total_score != null ? (
                          <span
                            className={cn(
                              "font-bold",
                              scan.total_score > 80 ? "text-green-600"
                                : scan.total_score > 60 ? "text-yellow-600"
                                : "text-red-600",
                            )}
                            aria-label={`${scan.total_score} (${scan.total_score > 80 ? "good" : scan.total_score > 60 ? "fair" : "poor"})`}
                          >
                            {scan.total_score}
                          </span>
                        ) : <span className="text-muted-foreground">--</span>}
                      </TableCell>
                      <TableCell>
                        {totalFindings > 0 ? (
                          <Badge variant="secondary">{totalFindings}</Badge>
                        ) : <span className="text-muted-foreground">0</span>}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {formatDate(scan.completed_at || scan.created_at, "Pp")}
                      </TableCell>
                      <TableCell>
                        <Select
                          value={state.format}
                          onValueChange={(v) => setRow(scan.id, { format: v as FormatValue })}
                          disabled={busy}
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {FORMATS.map((f) => (
                              <SelectItem key={f.value} value={f.value}>
                                <span className="font-medium">{f.label}</span>
                                <span className="ml-2 text-xs text-muted-foreground">
                                  {t(`formatHints.${f.value}` as any)}
                                </span>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </TableCell>
                      <TableCell className="text-right">
                        {state.phase === "ready" ? (
                          <div className="flex justify-end gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setRow(scan.id, { phase: "idle", taskId: undefined })}
                            >
                              {t("reset")}
                            </Button>
                            <Button size="sm" onClick={() => handleDownload(scan.id)}>
                              <Download className="mr-2 h-4 w-4" />
                              {t("download")}
                            </Button>
                          </div>
                        ) : (
                          <Button
                            size="sm"
                            onClick={() => handleGenerate(scan.id, state.format)}
                            disabled={busy}
                          >
                            {busy ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                {state.phase === "queued" ? t("queuing") : t("generating")}
                              </>
                            ) : (
                              <>
                                <FileText className="mr-2 h-4 w-4" />
                                {t("generate")}
                              </>
                            )}
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Mirror the pagination control from /dashboard/scans for consistency.
          v2.4.17 audit S-DRA-04: previously the labels were hardcoded
          English ("Previous" / "Page N" / "Next"). Re-uses the same
          three keys the scans table already has in the `scans`
          namespace so we don't duplicate translations. */}
      {data && data.total > 20 && (
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            {ts("previous")}
          </Button>
          <span className="text-sm text-muted-foreground">{ts("page", { n: page })}</span>
          <Button
            variant="outline"
            size="sm"
            disabled={scans.length < 20}
            onClick={() => setPage(page + 1)}
          >
            {ts("next")}
          </Button>
        </div>
      )}
    </div>
  )
}
