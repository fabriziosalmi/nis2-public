"use client"

import Link from "next/link"
import { Plus, Loader2, CalendarClock, Radar } from "lucide-react"
import { format } from "date-fns"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useScans } from "@/hooks/use-scans"
import { cn } from "@/lib/utils"
import { useState } from "react"

function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, string> = {
    pending: "border-yellow-500 text-yellow-600 bg-yellow-50",
    running: "border-blue-500 text-blue-600 bg-blue-50 animate-pulse",
    completed: "border-green-500 text-green-600 bg-green-50",
    failed: "border-red-500 text-red-600 bg-red-50",
    cancelled: "border-gray-400 text-gray-500 bg-gray-50",
  }
  return (
    <Badge variant="outline" className={variants[status] || ""}>
      {status}
    </Badge>
  )
}

export default function ScansPage() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useScans(page)
  const scans = data?.items || []
  const total = data?.total || 0

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scans</h1>
          <p className="text-muted-foreground">Manage and monitor your compliance scans</p>
        </div>
        <div className="flex gap-2 shrink-0">
          <Button variant="outline" asChild>
            <Link href="/dashboard/scans/schedules">
              <CalendarClock className="mr-2 h-4 w-4" />
              Schedules
            </Link>
          </Button>
          <Button asChild>
            <Link href="/dashboard/scans/new">
              <Plus className="mr-2 h-4 w-4" />
              New Scan
            </Link>
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center px-4">
              <div className="rounded-full bg-muted p-4 mb-4">
                <Radar className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-medium mb-1">No scans yet</h3>
              <p className="text-sm text-muted-foreground mb-6 max-w-sm">
                Run your first compliance scan to assess your infrastructure against NIS2 requirements.
              </p>
              <Button asChild>
                <Link href="/dashboard/scans/new">
                  <Plus className="mr-2 h-4 w-4" />
                  Run First Scan
                </Link>
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Hosts</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Date</TableHead>
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
                      {scan.total_score !== null && scan.total_score !== undefined ? (
                        <span className={cn("font-bold",
                          scan.total_score > 80 ? "text-green-600" : scan.total_score > 60 ? "text-yellow-600" : "text-red-600"
                        )}>{scan.total_score}</span>
                      ) : <span className="text-muted-foreground">--</span>}
                    </TableCell>
                    <TableCell>{scan.hosts_scanned || 0}</TableCell>
                    <TableCell>{(scan.findings_critical || 0) + (scan.findings_high || 0) + (scan.findings_medium || 0) + (scan.findings_low || 0)}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {scan.created_at ? format(new Date(scan.created_at), "MMM d, yyyy HH:mm") : "--"}
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
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button>
          <span className="text-sm text-muted-foreground">Page {page}</span>
          <Button variant="outline" size="sm" disabled={scans.length < 20} onClick={() => setPage(page + 1)}>Next</Button>
        </div>
      )}
    </div>
  )
}
