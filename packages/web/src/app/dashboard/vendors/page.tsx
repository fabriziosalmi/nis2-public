// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Network, ShieldCheck, AlertTriangle, Loader2, Boxes, Plus, Pencil, Trash2 } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { EntityFormDialog, type FieldSpec, type EntityValues } from "@/components/forms/entity-form-dialog"
import { useVendors, useVendorStats, useCreateVendor, useUpdateVendor, useDeleteVendor } from "@/hooks/use-vendors"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { AcnExportButton } from "@/components/export/acn-export-button"
import { api } from "@/lib/api-client"

const critVariant: Record<number, "critical" | "high" | "medium" | "low"> = {
  1: "critical", 2: "high", 3: "medium", 4: "low",
}

function StatCard({ icon, value, label, danger }: { icon: React.ReactNode; value: React.ReactNode; label: string; danger?: boolean }) {
  return (
    <Card className={danger ? "border-destructive/30" : undefined}>
      <CardContent className="flex items-center gap-4 py-5">
        <div className={`rounded-full p-3 ${danger ? "bg-destructive/10" : "bg-primary/10"}`}>{icon}</div>
        <div>
          <p className="text-2xl font-bold tabular-nums">{value}</p>
          <p className="text-sm text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export default function VendorsPage() {
  const t = useTranslations("vendors")
  const tc = useTranslations("common")
  useDocumentTitle(t("title"))

  const { data, isLoading } = useVendors()
  const { data: stats } = useVendorStats()
  const createVendor = useCreateVendor()
  const updateVendor = useUpdateVendor()
  const deleteVendor = useDeleteVendor()
  const items: any[] = data?.items ?? []

  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<any | null>(null)

  // Field set mirrors VendorCreate in app/routers/vendors.py. The criticality
  // and data-access scales are the ones the Art. 18 scoring formula reads, so
  // they are offered as fixed choices rather than free text.
  const fields: FieldSpec[] = [
    { name: "name", label: t("colName"), type: "text", required: true, full: true },
    { name: "vendor_type", label: t("colType"), type: "select", options: [
      { value: "ict_service", label: t("typeIctService") },
      { value: "cloud", label: t("typeCloud") },
      { value: "software", label: t("typeSoftware") },
      { value: "hardware", label: t("typeHardware") },
      { value: "consulting", label: t("typeConsulting") },
      { value: "other", label: t("typeOther") },
    ] },
    { name: "criticality", label: t("colCriticality"), type: "select", options: [
      { value: "1", label: t("crit1") }, { value: "2", label: t("crit2") },
      { value: "3", label: t("crit3") }, { value: "4", label: t("crit4") },
    ] },
    { name: "data_access_level", label: t("colAccess"), type: "select", options: [
      { value: "none", label: t("none") },
      { value: "metadata", label: t("accessMetadata") },
      { value: "personal", label: t("accessPersonal") },
      { value: "sensitive", label: t("accessSensitive") },
    ] },
    { name: "geographic_location", label: t("colLocation"), type: "text", placeholder: "IT / EU / US" },
    { name: "contact_name", label: t("contactName"), type: "text" },
    { name: "contact_email", label: t("contactEmail"), type: "email" },
    { name: "contract_ref", label: t("contractRef"), type: "text" },
    { name: "contract_expiry", label: t("contractExpiry"), type: "date" },
    { name: "has_security_certification", label: t("colCert"), type: "text", placeholder: "ISO 27001, SOC 2…" },
    { name: "last_audit_date", label: t("lastAudit"), type: "date" },
    { name: "next_audit_date", label: t("nextAudit"), type: "date" },
    { name: "security_score", label: t("colScore"), type: "number", min: 0, max: 100,
      hint: t("scoreHint") },
    { name: "services_provided", label: t("servicesProvided"), type: "textarea" },
    { name: "risk_notes", label: t("riskNotes"), type: "textarea" },
    { name: "acn_rilevanza_art18", label: t("acnRelevant"), type: "checkbox" },
  ]

  const openCreate = () => { setEditing(null); setDialogOpen(true) }
  const openEdit = (vendor: any) => { setEditing(vendor); setDialogOpen(true) }

  const submit = async (values: EntityValues) => {
    // The select yields strings; criticality is an int in the API.
    if (values.criticality !== undefined) values.criticality = Number(values.criticality)
    try {
      if (editing) {
        await updateVendor.mutateAsync({ id: editing.id, data: values })
        toast.success(t("vendorUpdated"))
      } else {
        await createVendor.mutateAsync(values)
        toast.success(t("vendorCreated"))
      }
      setDialogOpen(false)
    } catch (err: any) {
      toast.error(editing ? t("vendorUpdateFailed") : t("vendorCreateFailed"), { description: err.message })
    }
  }

  const remove = async (vendor: any) => {
    if (!window.confirm(tc("confirmDelete"))) return
    try {
      await deleteVendor.mutateAsync(vendor.id)
      toast.success(t("vendorDeleted"))
    } catch (err: any) {
      toast.error(t("vendorDeleteFailed"), { description: err.message })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <Network className="h-6 w-6 text-primary" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        </div>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <div className="flex flex-wrap justify-end gap-2">
        <AcnExportButton kind="art18" fetcher={() => api.exportAcnArt18()} />
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          {t("addVendor")}
        </Button>
      </div>

      {stats && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard icon={<Boxes className="h-5 w-5 text-primary" aria-hidden="true" />} value={stats.total ?? 0} label={t("total")} />
          <StatCard icon={<ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />} value={stats.art18_relevant ?? 0} label={t("art18")} />
          <StatCard icon={<AlertTriangle className="h-5 w-5 text-destructive" aria-hidden="true" />} value={stats.without_audit ?? 0} label={t("withoutAudit")} danger={(stats.without_audit ?? 0) > 0} />
          <StatCard icon={<ShieldCheck className="h-5 w-5 text-primary" aria-hidden="true" />} value={stats.avg_security_score ?? "—"} label={t("avgScore")} />
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
                <Network className="h-9 w-9 text-primary opacity-80" aria-hidden="true" />
              </div>
              <h3 className="text-xl font-semibold mb-1.5">{t("noVendors")}</h3>
              <p className="text-muted-foreground max-w-md">{t("noVendorsDesc")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("colName")}</TableHead>
                  <TableHead className="w-28">{t("colCriticality")}</TableHead>
                  <TableHead>{t("colType")}</TableHead>
                  <TableHead className="w-28">{t("colAccess")}</TableHead>
                  <TableHead className="w-24">{t("colLocation")}</TableHead>
                  <TableHead className="w-24">{t("colScore")}</TableHead>
                  <TableHead className="w-32">{t("colCert")}</TableHead>
                  <TableHead className="w-24 text-right">{tc("actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((v) => {
                  const score = v.security_score
                  const scoreTone = score == null ? "text-muted-foreground" : score >= 70 ? "text-emerald-600 dark:text-emerald-400" : score >= 50 ? "text-amber-600 dark:text-amber-400" : "text-destructive"
                  return (
                    <TableRow key={v.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{v.name}</span>
                          {v.acn_rilevanza_art18 && <Badge variant="secondary" className="text-[10px]">Art. 18</Badge>}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={critVariant[v.criticality] ?? "medium"}>{t(`crit${v.criticality}`)}</Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{v.vendor_type}</TableCell>
                      <TableCell className="text-sm capitalize">{v.data_access_level || t("none")}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{v.geographic_location || "—"}</TableCell>
                      <TableCell className={`font-semibold tabular-nums ${scoreTone}`}>{score ?? "—"}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{v.has_security_certification || "—"}</TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="sm" onClick={() => openEdit(v)} aria-label={tc("edit")} title={tc("edit")}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="sm" onClick={() => remove(v)} aria-label={tc("delete")} title={tc("delete")}>
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <EntityFormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={editing ? t("editVendor") : t("addVendor")}
        description={t("formDescription")}
        fields={fields}
        initialValues={editing ?? undefined}
        submitting={createVendor.isPending || updateVendor.isPending}
        onSubmit={submit}
      />
    </div>
  )
}
