// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import Link from "next/link"
import { Plus, Loader2, CalendarClock, Radar, Ban } from "lucide-react"
import { useFormatDate } from "@/lib/dates"
import { useTranslations } from "next-intl"
import { toast } from "sonner"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useScans, useCancelScan } from "@/hooks/use-scans"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"
import { useState } from "react"
import { TableSkeleton } from "@/components/ui/skeleton"

function StatusBadge({ status }: { status: string }) {
  const t = useTranslations("scans")
  const variants: Record<string, string> = {
    pending: "border-amber-500/30 text-amber-600 dark:text-amber-500 bg-amber-500/10",
    running: "border-blue-500/30 text-blue-600 dark:text-blue-500 bg-blue-500/10 animate-pulse shadow-[0_0_8px_rgba(59,130,246,0.3)]",
    completed: "border-emerald-500/30 text-emerald-600 dark:text-emerald-500 bg-emerald-500/10",
    failed: "border-red-500/30 text-red-600 dark:text-red-500 bg-red-500/10",
    cancelled: "border-slate-500/30 text-slate-600 dark:text-slate-400 bg-slate-500/10",
  }
  // Status string from the API matches a translation key; fall back to the
  // raw value if a future status appears that we haven't localised yet.
  const known = ["pending", "running", "completed", "failed", "cancelled"]
  return (
    <Badge variant="outline" className={variants[status] || ""}>
      {known.includes(status) ? t(status as any) : status}
    </Badge>
  )
}

export default function ScansPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useScans(page)
  const t = useTranslations("scans")
  const formatDate = useFormatDate()
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const scans = data?.items || []
  const total = data?.total || 0
  const cancelScan = useCancelScan()

  const handleCancel = async (e: React.MouseEvent, id: string) => {
    e.preventDefault()
    e.stopPropagation()
    try {
      await cancelScan.mutateAsync(id)
      toast.success(t("scanCancelled", { defaultValue: "Scan cancelled successfully" }))
    } catch (err: any) {
      toast.error(t("cancelFailed", { defaultValue: "Failed to cancel scan" }), { description: err.message })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <div className="flex gap-2 shrink-0">
          <Button variant="outline" asChild>
            <Link href="/dashboard/scans/schedules">
              <CalendarClock className="mr-2 h-4 w-4" />
              {t("schedules")}
            </Link>
          </Button>
          <Button asChild>
            <Link href="/dashboard/scans/new">
              <Plus className="mr-2 h-4 w-4" />
              {t("newScan")}
            </Link>
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <TableSkeleton columns={6} rows={5} />
          ) : scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-24 text-center px-4 relative overflow-hidden bg-card/30">
              <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(150,150,150,0.1) 1px, transparent 0)', backgroundSize: '24px 24px' }}></div>
              <div className="absolute inset-0 pointer-events-none bg-gradient-to-b from-transparent to-card/80"></div>
              
              <div className="relative z-10 rounded-full border border-primary/20 bg-primary/5 p-6 mb-6 shadow-2xl">
                <Radar className="h-10 w-10 text-primary opacity-80" />
              </div>
              <h3 className="relative z-10 text-2xl font-semibold mb-2 tracking-tight">{t("noScansYet")}</h3>
              <p className="relative z-10 text-muted-foreground max-w-md mb-8">
                {t("noScansDescription")}
              </p>
              <div className="relative z-10">
                <Button asChild className="shadow-lg shadow-primary/20 transition-all hover:scale-105">
                  <Link href="/dashboard/scans/new">
                    <Plus className="mr-2 h-4 w-4" />
                    {t("runFirstScan")}
                  </Link>
                </Button>
              </div>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("name")}</TableHead>
                  <TableHead>{t("status")}</TableHead>
                  <TableHead>{t("score")}</TableHead>
                  <TableHead>{t("hosts")}</TableHead>
                  <TableHead>{t("findings")}</TableHead>
                  <TableHead>{t("date")}</TableHead>
                  <TableHead className="w-[100px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan: any) => (
                  <TableRow key={scan.id} className="cursor-pointer hover:bg-muted/50">
                    <TableCell className="font-medium">
                      <Link href={`/dashboard/scans/${scan.id}`} className="hover:underline">
                        {scan.name}
                      </Link>
                    </TableCell>
                    <TableCell><StatusBadge status={scan.status} /></TableCell>
                    <TableCell>
                      {/* v2.4.23 audit a11y-05: aria-label surfaces
                          the band (good/fair/poor) so the
                          colour-coded score is not colour-only. */}
                      {scan.total_score !== null && scan.total_score !== undefined ? (
                        <span
                          className={cn("font-bold",
                            scan.total_score > 80 ? "text-green-600" : scan.total_score > 60 ? "text-yellow-600" : "text-red-600"
                          )}
                          aria-label={`${scan.total_score} (${scan.total_score > 80 ? "good" : scan.total_score > 60 ? "fair" : "poor"})`}
                        >{scan.total_score}</span>
                      ) : <span className="text-muted-foreground">--</span>}
                    </TableCell>
                    <TableCell>{scan.hosts_scanned || 0}</TableCell>
                    <TableCell>{(scan.findings_critical || 0) + (scan.findings_high || 0) + (scan.findings_medium || 0) + (scan.findings_low || 0)}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {formatDate(scan.created_at, "Pp")}
                    </TableCell>
                    <TableCell className="text-right">
                      {(scan.status === "running" || scan.status === "pending") && (
                        <Button variant="ghost" size="sm" onClick={(e) => handleCancel(e, scan.id)} disabled={cancelScan.isPending}>
                          <Ban className="h-4 w-4 text-muted-foreground" aria-label="Cancel Scan" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {total > 20 && (
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>{t("previous")}</Button>
          <span className="text-sm text-muted-foreground">{t("page", { n: page })}</span>
          <Button variant="outline" size="sm" disabled={scans.length < 20} onClick={() => setPage(page + 1)}>{t("next")}</Button>
        </div>
      )}
    </div>
  )
}
