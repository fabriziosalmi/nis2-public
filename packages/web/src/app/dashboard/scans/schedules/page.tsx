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
import { useTranslations } from "next-intl"
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
import { useDocumentTitle } from "@/hooks/use-document-title"
import { useFormatDate } from "@/lib/dates"

// v2.4.17 audit S-DRA-03: cron validation. Previously the schema
// only required `min(5)` chars, so "abcde" passed and the API
// returned a generic 422 with no actionable hint. The regex here
// validates the 5-field shape (minute / hour / day / month / DoW),
// allowing numbers, lists (1,2,3), ranges (1-5), wildcards (*) and
// steps (*/2). Field-level semantics (range bounds, valid steps)
// are still enforced by croniter on the server — this regex is
// just a fast-fail to give the user a clear error before round-trip.
//
// Error strings are i18n keys resolved via t(error.message) at
// render — same pattern as login/register/profile/etc.
const CRON_REGEX = /^\s*[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s+[\d*/,\-]+\s*$/

const scheduleSchema = z.object({
  name: z.string().min(1, "nameRequired"),
  cron_expression: z
    .string()
    .min(5, "cronRequired")
    .regex(CRON_REGEX, "cronInvalid"),
})

type ScheduleForm = z.infer<typeof scheduleSchema>

// Preset value strings (cron expressions) are stable; the labels are
// resolved through i18n at render time.
const cronPresetKeys = [
  { key: "dailyAt9", value: "0 9 * * *" },
  { key: "weeklyMonday", value: "0 9 * * 1" },
  { key: "biweekly", value: "0 9 1,15 * *" },
  { key: "monthlyFirst", value: "0 9 1 * *" },
  { key: "weekdaysAt8", value: "0 8 * * 1-5" },
] as const

export default function SchedulesPage() {
  const t = useTranslations("schedulesPage")
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const formatDate = useFormatDate()
  const user = useAuthStore((s) => s.user)
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
    if (!user) return
    try {
      const data = await api.listSchedules()
      setSchedules(Array.isArray(data) ? data : [])
    } catch { /* empty */ }
  }

  useEffect(() => { loadSchedules() }, [user])

  const onSubmit = async (data: ScheduleForm) => {
    if (selectedAssets.length === 0) {
      toast.error(t("selectAtLeastOne"))
      return
    }
    setLoading(true)
    try {
      await api.createSchedule({
        ...data,
        asset_ids: selectedAssets,
        scan_type: "full",
      })
      toast.success(t("created"))
      reset()
      setSelectedAssets([])
      setShowCreate(false)
      loadSchedules()
    } catch (err: any) {
      toast.error(t("createFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const toggleSchedule = async (id: string, isActive: boolean) => {
    try {
      await api.updateSchedule(id, { is_active: !isActive })
      toast.success(isActive ? t("pausedToast") : t("activatedToast"))
      loadSchedules()
    } catch (err: any) {
      toast.error(t("updateFailed"), { description: err.message })
    }
  }

  const deleteSchedule = async (id: string) => {
    try {
      await api.deleteSchedule(id)
      toast.success(t("deleted"))
      loadSchedules()
    } catch (err: any) {
      toast.error(t("deleteFailed"), { description: err.message })
    }
  }

  const triggerNow = async (id: string) => {
    setTriggering(id)
    try {
      await api.triggerSchedule(id)
      toast.success(t("triggered"))
      loadSchedules()
    } catch (err: any) {
      toast.error(t("triggerFailed"), { description: err.message })
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
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Button onClick={() => setShowCreate(!showCreate)}>
          <Plus className="mr-2 h-4 w-4" />
          {t("newSchedule")}
        </Button>
      </div>

      {showCreate && (
        <Card>
          <CardHeader>
            <CardTitle>{t("createTitle")}</CardTitle>
            <CardDescription>{t("createDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-2">
                <Label>{t("scheduleName")}</Label>
                <Input placeholder={t("scheduleNamePlaceholder")} {...register("name")} />
                {errors.name && (
                  <p className="text-xs text-destructive">{t(errors.name.message as any)}</p>
                )}
              </div>

              <div className="space-y-2">
                <Label>{t("cronExpression")}</Label>
                <Input placeholder="0 9 * * 1" {...register("cron_expression")} />
                {errors.cron_expression && (
                  <p className="text-xs text-destructive">
                    {t(errors.cron_expression.message as any)}
                  </p>
                )}
                <p className="text-xs text-muted-foreground">{t("cronHelp")}</p>
                <div className="flex flex-wrap gap-2 mt-2">
                  {cronPresetKeys.map((p) => (
                    <Badge
                      key={p.value}
                      variant="outline"
                      className="cursor-pointer hover:bg-muted"
                      onClick={() => setValue("cron_expression", p.value)}
                    >
                      {t(`presets.${p.key}` as any)}
                    </Badge>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <Label>{t("assetsToScan")}</Label>
                {assets.length === 0 ? (
                  <p className="text-sm text-muted-foreground">{t("noAssetsYet")}</p>
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
                <Button type="button" variant="outline" onClick={() => setShowCreate(false)}>{tc("cancel")}</Button>
                <Button type="submit" disabled={loading}>
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {t("create")}
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
            {t("activeSchedules")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {schedules.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Clock className="h-8 w-8 mx-auto mb-2 opacity-50" />
              <p>{t("noSchedulesYet")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("name")}</TableHead>
                  <TableHead>{t("schedule")}</TableHead>
                  <TableHead>{t("status")}</TableHead>
                  <TableHead>{t("lastRun")}</TableHead>
                  <TableHead className="text-right">{t("actions")}</TableHead>
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
                        {s.is_active ? t("active") : t("paused")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {s.last_run_at ? formatDate(s.last_run_at, "Pp") : t("never")}
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
