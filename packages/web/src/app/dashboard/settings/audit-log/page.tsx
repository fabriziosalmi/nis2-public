// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { ScrollText, Loader2 } from "lucide-react"
import { useTranslations } from "next-intl"
import { useFormatDate } from "@/lib/dates"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAuditLogs } from "@/hooks/use-audit-logs"
import { useDocumentTitle } from "@/hooks/use-document-title"

// Severity-ish colour buckets for the action namespace prefix.
// Doesn't try to be exhaustive — anything unknown falls back to muted.
const actionColors: Record<string, string> = {
  user: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  scan: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
  asset: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
  finding: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
  member: "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
  api_key: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
}

export default function AuditLogPage() {
  const t = useTranslations("auditLogPage")
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  // Pagination strings (previous / next / page) live in the `scans`
  // namespace — same widget rides on /scans, /reports, here, and
  // every other paginated table. Reusing keeps the translations in
  // one place. v2.4.19: previously this page called `tc("page")`
  // (common namespace, which has no `page` key) and fell back to a
  // literal English "Page X" via a `||` chain — but next-intl's
  // `t()` throws on missing keys rather than returning falsy, so
  // the page broke at runtime in IT/FR/DE/ES with a console
  // MISSING_MESSAGE error and a React error boundary trip.
  const ts = useTranslations("scans")
  const formatDate = useFormatDate()
  const [page, setPage] = useState(1)
  const { data, isLoading } = useAuditLogs({ page, page_size: 50 })

  const items = data?.items || []
  const total = data?.total || 0

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ScrollText className="h-5 w-5" />
            {t("activity")}
          </CardTitle>
          <CardDescription>{t("activityDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : items.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center px-4">
              <h3 className="text-lg font-medium mb-1">{t("noEntries")}</h3>
              <p className="text-sm text-muted-foreground max-w-sm">{t("noEntriesDescription")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("action")}</TableHead>
                  <TableHead>{t("user")}</TableHead>
                  <TableHead>{t("details")}</TableHead>
                  <TableHead>{t("ip")}</TableHead>
                  <TableHead>{t("time")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((row: any) => {
                  // `member.role_changed` → bucket "member". Anything
                  // before the first dot is the namespace.
                  const namespace = row.action.split(".")[0]
                  const colourClass = actionColors[namespace] || ""
                  // Compress the `details` JSON into a one-line preview.
                  // Full inspection happens in a future detail view; right
                  // now we just want the auditor to see what changed at a
                  // glance.
                  const detailsPreview = row.details && Object.keys(row.details).length > 0
                    ? Object.entries(row.details)
                        .slice(0, 3)
                        .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
                        .join(", ")
                    : ""
                  const actorLabel = row.actor?.email || row.actor?.full_name || t("system")
                  return (
                    <TableRow key={row.id}>
                      <TableCell>
                        <Badge variant="secondary" className={`font-mono text-xs ${colourClass}`}>
                          {row.action}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">{actorLabel}</TableCell>
                      <TableCell className="text-sm text-muted-foreground max-w-md truncate">
                        {detailsPreview || row.resource_type}
                      </TableCell>
                      <TableCell className="text-xs font-mono text-muted-foreground">
                        {row.ip_address || "—"}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                        {formatDate(row.created_at, "Pp")}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {total > 50 && (
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            {ts("previous")}
          </Button>
          <span className="text-sm text-muted-foreground">{ts("page", { n: page })}</span>
          <Button
            variant="outline"
            size="sm"
            disabled={items.length < 50}
            onClick={() => setPage(page + 1)}
          >
            {ts("next")}
          </Button>
        </div>
      )}
    </div>
  )
}
