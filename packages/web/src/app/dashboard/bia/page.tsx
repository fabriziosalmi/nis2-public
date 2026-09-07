// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Activity, ShieldCheck, LifeBuoy, Loader2, Plus, Pencil, Trash2 } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { EntityFormDialog, type FieldSpec, type EntityValues } from "@/components/forms/entity-form-dialog"
import { useBia, useCreateBiaProcess, useUpdateBiaProcess, useDeleteBiaProcess } from "@/hooks/use-bia"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { AcnExportButton } from "@/components/export/acn-export-button"
import { api } from "@/lib/api-client"
import { cn } from "@/lib/utils"

const critVariant: Record<number, "critical" | "high" | "medium" | "low"> = {
  1: "critical", 2: "high", 3: "medium", 4: "low", 5: "low",
}

function StatCard({ icon, value, label }: { icon: React.ReactNode; value: React.ReactNode; label: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 py-5">
        <div className="rounded-full bg-primary/10 p-3">{icon}</div>
        <div>
          <p className="text-2xl font-bold tabular-nums">{value}</p>
          <p className="text-sm text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export default function BiaPage() {
  const t = useTranslations("bia")
  useDocumentTitle(t("title"))

  const tc = useTranslations("common")
  const { data, isLoading } = useBia()
  const createProcess = useCreateBiaProcess()
  const updateProcess = useUpdateBiaProcess()
  const deleteProcess = useDeleteBiaProcess()
  const items: any[] = data?.items ?? []

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<any | null>(null)

  const scale4 = (prefix: string) => [1, 2, 3, 4].map((n) => ({
    value: String(n), label: t(`${prefix}${n}`),
  }))

  // Mirrors ProcessCreate in app/routers/bia.py. RTO/RPO/MTPD are the values a
  // BIA exists to record, and the five impact dimensions are what the matrix
  // and the gap detection read.
  const fields: FieldSpec[] = [
    { name: "name", label: t("colProcess"), type: "text", required: true, full: true },
    { name: "process_owner", label: t("colOwner"), type: "text" },
    { name: "department", label: t("department"), type: "text" },
    { name: "criticality_level", label: t("colCriticality"), type: "select", options: scale4("crit") },
    { name: "rto_hours", label: t("colRto"), type: "number", min: 0, hint: t("rtoHint") },
    { name: "rpo_hours", label: t("colRpo"), type: "number", min: 0, hint: t("rpoHint") },
    { name: "mtpd_hours", label: t("colMtpd"), type: "number", min: 0, hint: t("mtpdHint") },
    { name: "impact_financial", label: t("impactFinancial"), type: "select", options: scale4("impact") },
    { name: "impact_operational", label: t("impactOperational"), type: "select", options: scale4("impact") },
    { name: "impact_reputational", label: t("impactReputational"), type: "select", options: scale4("impact") },
    { name: "impact_regulatory", label: t("impactRegulatory"), type: "select", options: scale4("impact") },
    { name: "impact_safety", label: t("impactSafety"), type: "select", options: scale4("impact") },
    { name: "has_bcp", label: t("hasBcp"), type: "checkbox" },
    { name: "has_drp", label: t("hasDrp"), type: "checkbox" },
    { name: "acn_servizio_essenziale", label: t("acnEssential"), type: "checkbox" },
    { name: "description", label: t("description"), type: "textarea" },
    { name: "notes", label: t("notes"), type: "textarea" },
  ]

  const NUMERIC_SELECTS = [
    "criticality_level", "impact_financial", "impact_operational",
    "impact_reputational", "impact_regulatory", "impact_safety",
  ]

  const openCreate = () => { setEditing(null); setDialogOpen(true) }
  const openEdit = (proc: any) => { setEditing(proc); setDialogOpen(true) }

  const submit = async (values: EntityValues) => {
    for (const key of NUMERIC_SELECTS) {
      if (values[key] !== undefined) values[key] = Number(values[key])
    }
    try {
      if (editing) {
        await updateProcess.mutateAsync({ id: editing.id, data: values })
        toast.success(t("processUpdated"))
      } else {
        await createProcess.mutateAsync(values)
        toast.success(t("processCreated"))
      }
      setDialogOpen(false)
    } catch (err: any) {
      toast.error(editing ? t("processUpdateFailed") : t("processCreateFailed"), { description: err.message })
    }
  }

  const remove = async (proc: any) => {
    if (!window.confirm(tc("confirmDelete"))) return
    try {
      await deleteProcess.mutateAsync(proc.id)
      toast.success(t("processDeleted"))
    } catch (err: any) {
      toast.error(t("processDeleteFailed"), { description: err.message })
    }
  }
  const essential = items.filter((p) => p.acn_servizio_essenziale).length
  const withPlans = items.filter((p) => p.has_bcp && p.has_drp).length
  const h = (v: number | null | undefined) => (v == null ? "—" : `${v}${t("hours")}`)

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <Activity className="h-6 w-6 text-primary" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        </div>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <div className="flex flex-wrap justify-end gap-2">
        <AcnExportButton kind="bia" fetcher={() => api.exportAcnBia()} />
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          {t("addProcess")}
        </Button>
      </div>

      {items.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-3 lg:max-w-2xl">
          <StatCard icon={<Activity className="h-5 w-5 text-primary" aria-hidden="true" />} value={items.length} label={t("totalProcesses")} />
          <StatCard icon={<ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />} value={essential} label={t("essentialCount")} />
          <StatCard icon={<LifeBuoy className="h-5 w-5 text-primary" aria-hidden="true" />} value={withPlans} label={t("withPlans")} />
        </div>
      )}

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : items.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center px-4">
              <div className="rounded-full border border-primary/20 bg-primary/5 p-6 mb-5">
                <Activity className="h-9 w-9 text-primary opacity-80" aria-hidden="true" />
              </div>
              <h3 className="text-xl font-semibold mb-1.5">{t("noProcesses")}</h3>
              <p className="text-muted-foreground max-w-md">{t("noProcessesDesc")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("colProcess")}</TableHead>
                  <TableHead className="w-28">{t("colCriticality")}</TableHead>
                  <TableHead className="w-40">{t("colOwner")}</TableHead>
                  <TableHead className="w-20 text-right">{t("colRto")}</TableHead>
                  <TableHead className="w-20 text-right">{t("colRpo")}</TableHead>
                  <TableHead className="w-20 text-right">{t("colMtpd")}</TableHead>
                  <TableHead className="w-32">{t("colContinuity")}</TableHead>
                  <TableHead className="w-24 text-right">{tc("actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{p.name}</span>
                        {p.acn_servizio_essenziale && <Badge variant="secondary" className="text-[10px]">{t("essential")}</Badge>}
                      </div>
                      {p.department && <p className="text-xs text-muted-foreground">{p.department}</p>}
                    </TableCell>
                    <TableCell>
                      <Badge variant={critVariant[p.criticality_level] ?? "medium"}>{t(`crit${p.criticality_level}`)}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{p.process_owner || "—"}</TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums">{h(p.rto_hours)}</TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums">{h(p.rpo_hours)}</TableCell>
                    <TableCell className="text-right font-mono text-sm tabular-nums">{h(p.mtpd_hours)}</TableCell>
                    <TableCell>
                      <div className="flex gap-1.5">
                        <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold", p.has_bcp ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : "bg-muted text-muted-foreground line-through")}>{t("bcp")}</span>
                        <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold", p.has_drp ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" : "bg-muted text-muted-foreground line-through")}>{t("drp")}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm" onClick={() => openEdit(p)} aria-label={tc("edit")} title={tc("edit")}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => remove(p)} aria-label={tc("delete")} title={tc("delete")}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <EntityFormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={editing ? t("editProcess") : t("addProcess")}
        description={t("formDescription")}
        fields={fields}
        initialValues={editing ?? undefined}
        submitting={createProcess.isPending || updateProcess.isPending}
        onSubmit={submit}
      />
    </div>
  )
}
