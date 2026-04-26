// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import {
  Clock, Plus, Trash2, Play, Pause, Loader2, CalendarClock, AlertCircle,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"
import { useAssets } from "@/hooks/use-assets"

const scheduleSchema = z.object({
  name: z.string().min(1, "Name is required"),
  cron_expression: z.string().min(5, "Cron expression required"),
})

type ScheduleForm = z.infer<typeof scheduleSchema>

const cronPresets = [
  { label: "Daily at 9 AM", value: "0 9 * * *" },
  { label: "Weekly Monday 9 AM", value: "0 9 * * 1" },
  { label: "Bi-weekly Monday", value: "0 9 1,15 * *" },
  { label: "Monthly 1st at 9 AM", value: "0 9 1 * *" },
  { label: "Weekdays at 8 AM", value: "0 8 * * 1-5" },
]

export default function SchedulesPage() {
  const token = useAuthStore((s) => s.token)
  const { data: assetsData } = useAssets()
  const [schedules, setSchedules] = useState<any[]>([])
  const [showCreate, setShowCreate] = useState(false)
  const [selectedAssets, setSelectedAssets] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [triggering, setTriggering] = useState<string | null>(null)

  const assets = assetsData?.items || []

  const { register, handleSubmit, setValue, reset, formState: { errors } } = useForm<ScheduleForm>({
    resolver: zodResolver(scheduleSchema),
  })

  const loadSchedules = async () => {
    if (!token) return
    try {
      const data = await api.listSchedules(token)
      setSchedules(Array.isArray(data) ? data : [])
    } catch { /* empty */ }
  }

  useEffect(() => { loadSchedules() }, [token])

  const onSubmit = async (data: ScheduleForm) => {
    if (!token) return
    if (selectedAssets.length === 0) {
      toast.error("Select at least one asset")
      return
    }
    setLoading(true)
    try {
      await api.createSchedule(token, {
        ...data,
        asset_ids: selectedAssets,
        scan_type: "full",
      })
      toast.success("Schedule created")
      reset()
      setSelectedAssets([])
      setShowCreate(false)
      loadSchedules()
    } catch (err: any) {
      toast.error("Failed to create schedule", { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const toggleSchedule = async (id: string, isActive: boolean) => {
    if (!token) return
    try {
      await api.updateSchedule(token, id, { is_active: !isActive })
      toast.success(isActive ? "Schedule paused" : "Schedule activated")
      loadSchedules()
    } catch (err: any) {
      toast.error("Update failed", { description: err.message })
    }
  }

  const deleteSchedule = async (id: string) => {
    if (!token) return
    try {
      await api.deleteSchedule(token, id)
      toast.success("Schedule deleted")
      loadSchedules()
    } catch (err: any) {
      toast.error("Delete failed", { description: err.message })
    }
  }

  const triggerNow = async (id: string) => {
    if (!token) return
    setTriggering(id)
    try {
      await api.triggerSchedule(token, id)
      toast.success("Scan triggered! Check the Scans page for progress.")
      loadSchedules()
    } catch (err: any) {
      toast.error("Trigger failed", { description: err.message })
    } finally {
      setTriggering(null)
    }
  }

  const toggleAsset = (id: string) => {
    setSelectedAssets((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id]
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Scheduled Scans</h1>
          <p className="text-muted-foreground">Automate recurring compliance scans</p>
        </div>
        <Button onClick={() => setShowCreate(!showCreate)}>
          <Plus className="mr-2 h-4 w-4" />
          New Schedule
        </Button>
      </div>

      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle>Create Schedule</CardTitle>
            <CardDescription>Define when and what to scan automatically</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-2">
                <Label>Schedule Name</Label>
                <Input placeholder="e.g. Weekly Production Audit" {...register("name")} />
                {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
              </div>

              <div className="space-y-2">
                <Label>Cron Expression</Label>
                <Input placeholder="0 9 * * 1" {...register("cron_expression")} />
                {errors.cron_expression && <p className="text-xs text-destructive">{errors.cron_expression.message}</p>}
                <div className="flex flex-wrap gap-2 mt-2">
                  {cronPresets.map((p) => (
                    <Badge
                      key={p.value}
                      variant="outline"
                      className="cursor-pointer hover:bg-muted"
                      onClick={() => setValue("cron_expression", p.value)}
                    >
                      {p.label}
                    </Badge>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <Label>Assets to scan</Label>
                {assets.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No assets yet. Add assets first.</p>
                ) : (
                  <div className="grid gap-2 md:grid-cols-2">
                    {assets.map((asset: any) => (
                      <div
                        key={asset.id}
                        className={`flex items-center gap-3 rounded-lg border p-3 cursor-pointer transition-colors ${
                          selectedAssets.includes(asset.id) ? "border-primary bg-primary/5" : "hover:bg-muted/50"
                        }`}
                        onClick={() => toggleAsset(asset.id)}
                      >
                        <input
                          type="checkbox"
                          checked={selectedAssets.includes(asset.id)}
                          onChange={() => toggleAsset(asset.id)}
                          className="rounded"
                        />
                        <div>
                          <p className="text-sm font-medium">{asset.name}</p>
                          <p className="text-xs text-muted-foreground">{asset.target_value}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <Separator />
              <div className="flex gap-2 justify-end">
                <Button type="button" variant="outline" onClick={() => setShowCreate(false)}>Cancel</Button>
                <Button type="submit" disabled={loading}>
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Create Schedule
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <CalendarClock className="h-5 w-5" />
            Active Schedules
          </CardTitle>
        </CardHeader>
        <CardContent>
          {schedules.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Clock className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>No scheduled scans yet.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Schedule</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last Run</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((s: any) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-medium">{s.name}</TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-2 py-1 rounded">{s.cron_expression}</code>
                    </TableCell>
                    <TableCell>
                      <Badge variant={s.is_active ? "default" : "secondary"}>
                        {s.is_active ? "Active" : "Paused"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "Never"}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex gap-1 justify-end">
                        <Button variant="ghost" size="icon" className="h-8 w-8"
                          onClick={() => triggerNow(s.id)} disabled={triggering === s.id}>
                          {triggering === s.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                        </Button>
                        <Button variant="ghost" size="icon" className="h-8 w-8"
                          onClick={() => toggleSchedule(s.id, s.is_active)}>
                          {s.is_active ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4 text-green-600" />}
                        </Button>
                        <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive"
                          onClick={() => deleteSchedule(s.id)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
