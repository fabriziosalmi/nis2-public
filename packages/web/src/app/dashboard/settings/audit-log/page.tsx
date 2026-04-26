// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { ScrollText, Filter } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

const sampleLogs = [
  { id: "1", action: "user.login", user: "admin@nis2platform.eu", resource: "auth", details: "Login from 192.168.1.100", created_at: "2026-03-28T21:09:00Z" },
  { id: "2", action: "scan.created", user: "admin@nis2platform.eu", resource: "scan", details: "Created scan 'Production Audit'", created_at: "2026-03-28T21:10:00Z" },
  { id: "3", action: "asset.created", user: "admin@nis2platform.eu", resource: "asset", details: "Added example.com", created_at: "2026-03-28T21:11:00Z" },
  { id: "4", action: "scan.completed", user: "system", resource: "scan", details: "Scan completed with score 73", created_at: "2026-03-28T21:25:00Z" },
  { id: "5", action: "finding.updated", user: "admin@nis2platform.eu", resource: "finding", details: "Status changed to acknowledged", created_at: "2026-03-28T21:30:00Z" },
  { id: "6", action: "member.invited", user: "admin@nis2platform.eu", resource: "team", details: "Invited auditor@company.com as auditor", created_at: "2026-03-28T21:35:00Z" },
  { id: "7", action: "api_key.created", user: "admin@nis2platform.eu", resource: "api_key", details: "Created key 'CI Pipeline'", created_at: "2026-03-28T21:40:00Z" },
]

const actionColors: Record<string, "default" | "secondary" | "outline" | "destructive"> = {
  "user.login": "secondary",
  "scan.created": "default",
  "scan.completed": "default",
  "asset.created": "outline",
  "finding.updated": "secondary",
  "member.invited": "outline",
  "api_key.created": "outline",
}

export default function AuditLogPage() {
  const [logs] = useState(sampleLogs)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Audit Log</h1>
          <p className="text-muted-foreground">Track all actions taken in your organization</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ScrollText className="h-5 w-5" />
            Activity
          </CardTitle>
          <CardDescription>Showing recent actions. Audit logs are retained for 90 days.</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Action</TableHead>
                <TableHead>User</TableHead>
                <TableHead>Details</TableHead>
                <TableHead>Time</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {logs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center py-8 text-muted-foreground">
                    No audit log entries yet
                  </TableCell>
                </TableRow>
              ) : (
                logs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>
                      <Badge variant={actionColors[log.action] || "secondary"} className="font-mono text-xs">
                        {log.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm">{log.user}</TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-xs truncate">{log.details}</TableCell>
                    <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
