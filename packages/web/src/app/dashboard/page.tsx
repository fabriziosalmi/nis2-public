// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import Link from "next/link"
import dynamic from "next/dynamic"
import { Suspense } from "react"
import { Radar, ShieldCheck, AlertTriangle, Server, Plus, ArrowUpRight, Loader2 } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useScans } from "@/hooks/use-scans"
import { useFindingStats } from "@/hooks/use-findings"
import { useAssets } from "@/hooks/use-assets"
import { cn } from "@/lib/utils"

// Lazy load Recharts (400KB+) — only loads when charts are visible
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const BarChart = dynamic(() => import("recharts").then(m => m.BarChart) as any, { ssr: false })
const Bar = dynamic(() => import("recharts").then(m => m.Bar) as any, { ssr: false })
const XAxis = dynamic(() => import("recharts").then(m => m.XAxis) as any, { ssr: false })
const YAxis = dynamic(() => import("recharts").then(m => m.YAxis) as any, { ssr: false })
const CartesianGrid = dynamic(() => import("recharts").then(m => m.CartesianGrid) as any, { ssr: false })
const Tooltip = dynamic(() => import("recharts").then(m => m.Tooltip) as any, { ssr: false })
const ResponsiveContainer = dynamic(() => import("recharts").then(m => m.ResponsiveContainer) as any, { ssr: false })
const LineChart = dynamic(() => import("recharts").then(m => m.LineChart) as any, { ssr: false })
const Line = dynamic(() => import("recharts").then(m => m.Line) as any, { ssr: false })
import { format } from "date-fns"

function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, string> = {
    pending: "border-yellow-500 text-yellow-600 bg-yellow-50",
    running: "border-blue-500 text-blue-600 bg-blue-50 animate-pulse",
    completed: "border-green-500 text-green-600 bg-green-50",
    failed: "border-red-500 text-red-600 bg-red-50",
  }
  return <Badge variant="outline" className={variants[status] || ""}>{status}</Badge>
}

function ScoreDisplay({ score }: { score: number | null | undefined }) {
  if (score === null || score === undefined) return <span className="text-muted-foreground">--</span>
  return (
    <span className={cn("font-bold", score > 80 ? "text-green-600" : score > 60 ? "text-yellow-600" : "text-red-600")}>
      {score}
    </span>
  )
}

export default function DashboardPage() {
  const { data: scansData, isLoading: scansLoading } = useScans()
  const { data: statsData } = useFindingStats()
  const { data: assetsData } = useAssets()

  const scans = scansData?.items || []
  const recentScans = scans.slice(0, 5)
  const hasData = scans.length > 0

  // Compute real stats
  const completedScans = scans.filter((s: any) => s.status === "completed" && s.total_score != null)
  const avgScore = completedScans.length > 0
    ? Math.round(completedScans.reduce((sum: number, s: any) => sum + s.total_score, 0) / completedScans.length)
    : null

  const totalFindings = scans.reduce((sum: number, s: any) =>
    sum + (s.findings_critical || 0) + (s.findings_high || 0) + (s.findings_medium || 0) + (s.findings_low || 0), 0)

  // Build chart data from real scans
  const severityChartData = hasData ? [
    { severity: "Critical", count: scans.reduce((s: number, sc: any) => s + (sc.findings_critical || 0), 0) },
    { severity: "High", count: scans.reduce((s: number, sc: any) => s + (sc.findings_high || 0), 0) },
    { severity: "Medium", count: scans.reduce((s: number, sc: any) => s + (sc.findings_medium || 0), 0) },
    { severity: "Low", count: scans.reduce((s: number, sc: any) => s + (sc.findings_low || 0), 0) },
  ] : []

  const trendData = completedScans
    .sort((a: any, b: any) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    .map((s: any) => ({
      date: format(new Date(s.created_at), "MMM d"),
      score: s.total_score,
    }))

  const stats = [
    {
      title: "Total Scans",
      value: scansData?.total?.toString() || "0",
      change: completedScans.length > 0 ? `${completedScans.length} completed` : "No scans yet",
      icon: Radar,
      bg: "bg-blue-500/10",
      iconColor: "text-blue-600",
    },
    {
      title: "Average Score",
      value: avgScore?.toString() || "--",
      change: avgScore ? (avgScore > 80 ? "Good compliance" : avgScore > 60 ? "Needs improvement" : "Action required") : "Run a scan",
      icon: ShieldCheck,
      bg: "bg-green-500/10",
      iconColor: "text-green-600",
    },
    {
      title: "Total Findings",
      value: totalFindings.toString(),
      change: statsData?.open ? `${statsData.open} open` : "Across all scans",
      icon: AlertTriangle,
      bg: "bg-orange-500/10",
      iconColor: "text-orange-600",
    },
    {
      title: "Assets Monitored",
      value: assetsData?.total?.toString() || "0",
      change: assetsData?.total > 0 ? "Active targets" : "Add assets to start",
      icon: Server,
      bg: "bg-purple-500/10",
      iconColor: "text-purple-600",
    },
  ]

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">NIS2 compliance overview and recent activity</p>
        </div>
        <Button asChild className="shrink-0 w-fit">
          <Link href="/dashboard/scans/new">
            <Plus className="mr-2 h-4 w-4" />
            New Scan
          </Link>
        </Button>
      </div>

      {/* Stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <Card key={stat.title}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">{stat.title}</CardTitle>
              <div className={cn("rounded-lg p-2", stat.bg)}>
                <stat.icon className={cn("h-4 w-4", stat.iconColor)} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stat.value}</div>
              <p className="text-xs text-muted-foreground">{stat.change}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts row - only show when there's data */}
      {hasData && (
        <div className="grid gap-4 lg:grid-cols-7">
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle>Findings by Severity</CardTitle>
              <CardDescription>Distribution across severity levels</CardDescription>
            </CardHeader>
            <CardContent>
              {severityChartData.some((d) => d.count > 0) ? (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={severityChartData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                    <XAxis type="number" />
                    <YAxis dataKey="severity" type="category" width={70} tick={{ fontSize: 12 }} />
                    <Tooltip contentStyle={{ borderRadius: "8px" }} />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} fill="hsl(222.2, 47.4%, 11.2%)" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-[260px] text-muted-foreground text-sm">No findings data</div>
              )}
            </CardContent>
          </Card>

          <Card className="lg:col-span-4">
            <CardHeader>
              <CardTitle>Compliance Score Trend</CardTitle>
              <CardDescription>Score progression across scans</CardDescription>
            </CardHeader>
            <CardContent>
              {trendData.length > 1 ? (
                <ResponsiveContainer width="100%" height={260}>
                  <LineChart data={trendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 12 }} />
                    <Tooltip contentStyle={{ borderRadius: "8px" }} />
                    <Line type="monotone" dataKey="score" stroke="hsl(222.2, 47.4%, 11.2%)" strokeWidth={2} dot={{ r: 3 }} activeDot={{ r: 5 }} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-[260px] text-muted-foreground text-sm">
                  {trendData.length === 1 ? "Need at least 2 scans for trend" : "No completed scans yet"}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Getting started - show when no data */}
      {!hasData && !scansLoading && (
        <Card className="border-dashed">
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <div className="rounded-full bg-primary/10 p-4 mb-4">
              <ShieldCheck className="h-10 w-10 text-primary" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Welcome to NIS2 Platform</h3>
            <p className="text-muted-foreground mb-6 max-w-md">
              Get started by adding your assets (domains, IPs) and running your first compliance scan against NIS2 Directive requirements.
            </p>
            <div className="flex gap-3">
              <Button variant="outline" asChild>
                <Link href="/dashboard/assets">
                  <Server className="mr-2 h-4 w-4" />
                  Add Assets
                </Link>
              </Button>
              <Button asChild>
                <Link href="/dashboard/scans/new">
                  <Radar className="mr-2 h-4 w-4" />
                  Run First Scan
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Recent scans */}
      {recentScans.length > 0 && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>Latest compliance scans and their results</CardDescription>
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link href="/dashboard/scans">
                View all
                <ArrowUpRight className="ml-1 h-3 w-3" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentScans.map((scan: any) => (
                  <TableRow key={scan.id} className="cursor-pointer">
                    <TableCell className="font-medium">
                      <Link href={`/dashboard/scans/${scan.id}`} className="hover:underline">{scan.name}</Link>
                    </TableCell>
                    <TableCell><StatusBadge status={scan.status} /></TableCell>
                    <TableCell><ScoreDisplay score={scan.total_score} /></TableCell>
                    <TableCell>{(scan.findings_critical || 0) + (scan.findings_high || 0) + (scan.findings_medium || 0) + (scan.findings_low || 0)}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {scan.created_at ? format(new Date(scan.created_at), "MMM d, yyyy") : "--"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Professional services CTA */}
      <Card className="bg-muted/30 border-muted">
        <CardContent className="flex flex-col sm:flex-row items-center justify-between gap-4 py-5">
          <div>
            <p className="text-sm font-medium">Need expert help with NIS2 compliance, certificate remediation, or custom assessments?</p>
            <p className="text-xs text-muted-foreground">Private scans, incident response, staff training, and ongoing monitoring available.</p>
          </div>
          <Button variant="outline" size="sm" asChild className="shrink-0">
            <a href="mailto:fabrizio.salmi@gmail.com">
              Request Consultation
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
