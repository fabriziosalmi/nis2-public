// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useEffect, useState } from "react"
import { useTranslations } from "next-intl"
import { Siren, Clock, CheckCircle2, AlertOctagon, Loader2, ShieldAlert, Plus, Pencil, Trash2 } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { EntityFormDialog, type FieldSpec, type EntityValues } from "@/components/forms/entity-form-dialog"
import { useIncidentMonitor, useCreateIncident, useUpdateIncident, useDeleteIncident, useRecordSubmission } from "@/hooks/use-incidents"
import { RedButtonDialog } from "@/components/incidents/red-button-dialog"
import { useDocumentTitle } from "@/hooks/use-document-title"
import { cn } from "@/lib/utils"
import { deadlineState, formatRemaining, type Deadline } from "@/lib/deadlines"

const severityVariant: Record<string, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
}

function DeadlineChip({
  title,
  deadline,
  isOpen,
  nowMs,
  onRecordSent,
  recording,
}: {
  title: string
  deadline: Deadline
  isOpen: boolean
  nowMs: number
  onRecordSent: () => void
  recording: boolean
}) {
  const t = useTranslations("incidents")
  // Derived in lib/deadlines so the arithmetic can be tested without a DOM.
  const state = deadlineState(deadline, isOpen, nowMs)
  if (!state) return null
  const { remainingMs, sent, overdue, urgent } = state

  const tone = sent
    ? "border-emerald-500/40 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400"
    : overdue
      ? "border-destructive/50 bg-destructive/10 text-destructive"
      : urgent
        ? "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        : "border-border bg-muted/40 text-foreground"

  return (
    <div className={cn("flex flex-col gap-1 rounded-lg border px-3 py-2 min-w-[9.5rem]", tone)}>
      <span className="text-[11px] font-medium uppercase tracking-wide opacity-80">{title}</span>
      <div className="flex items-center gap-1.5">
        {sent ? (
          <>
            <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="text-sm font-semibold">{t("sent")}</span>
          </>
        ) : overdue ? (
          <>
            <AlertOctagon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="font-mono text-sm font-semibold tabular-nums">{formatRemaining(remainingMs)}</span>
          </>
        ) : (
          <>
            <Clock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            <span className="font-mono text-sm font-semibold tabular-nums">{formatRemaining(remainingMs)}</span>
          </>
        )}
      </div>
      <span className="text-[10px] opacity-70">
        {sent ? new Date(deadline.sent_at!).toLocaleDateString() : overdue ? t("deadlinePassed") : t("remaining")}
      </span>
      {/* Without this the alerting could not be switched off by doing the thing
          it was alerting about: the `*_sent_at` columns were read in three
          places and written in none, so an operator who filed the Early Warning
          on time kept receiving breach alerts for it, daily. */}
      {isOpen && !sent && (
        <button
          type="button"
          onClick={onRecordSent}
          disabled={recording}
          className="mt-0.5 text-left text-[10px] font-medium underline underline-offset-2 opacity-80 hover:opacity-100 disabled:opacity-50"
        >
          {t("markSubmitted")}
        </button>
      )}
    </div>
  )
}

export default function IncidentsPage() {
  const t = useTranslations("incidents")
  useDocumentTitle(t("title"))

  const { data, isLoading } = useIncidentMonitor()

  // Live clock — re-render every second so the countdowns tick.
  const [nowMs, setNowMs] = useState<number>(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const items: any[] = data?.items ?? []
  const openCount = data?.open_count ?? 0
  const breachedCount = data?.breached_count ?? 0

  const tc = useTranslations("common")
  const createIncident = useCreateIncident()
  const updateIncident = useUpdateIncident()
  const deleteIncident = useDeleteIncident()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<any | null>(null)
  const [redButtonOpen, setRedButtonOpen] = useState(false)
  const recordSubmission = useRecordSubmission()

  // Recording is a claim about a filing that happened outside the platform —
  // CSIRT Italia has no API to submit to — so it asks for the reference the
  // portal returns. That reference is the only thing tying this row to the
  // actual submission, and it is what an auditor asks for.
  const markSubmitted = async (
    inc: any,
    obligation: "early_warning" | "notification" | "final_report",
  ) => {
    const reference = window.prompt(t("csirtReferencePrompt")) ?? undefined
    if (reference === undefined) return
    try {
      await recordSubmission.mutateAsync({
        id: inc.id,
        obligation,
        csirtReferenceId: reference.trim() || undefined,
      })
      toast.success(t("submissionRecorded"))
    } catch (err: any) {
      toast.error(t("submissionFailed"), { description: err.message })
    }
  }

  // Mirrors IncidentCreate in app/routers/incidents.py. The Art. 23 clocks run
  // from `detected_at`, so it is offered explicitly rather than defaulted to
  // now: an incident is very often entered some hours after it was noticed, and
  // starting the 24-hour early-warning countdown from data-entry time would
  // quietly report the wrong deadline.
  const fields: FieldSpec[] = [
    { name: "title", label: t("fieldTitle"), type: "text", required: true, full: true },
    { name: "incident_type", label: t("incidentType"), type: "select", required: true, options: [
      { value: "ransomware", label: t("type_ransomware") },
      { value: "data_breach", label: t("type_data_breach") },
      { value: "ddos", label: t("type_ddos") },
      { value: "supply_chain", label: t("type_supply_chain") },
      { value: "unauthorized_access", label: t("type_unauthorized_access") },
      { value: "malware", label: t("type_malware") },
      { value: "other", label: t("type_other") },
    ] },
    { name: "severity", label: t("severity"), type: "select", required: true, options: [
      { value: "low", label: t("sev_low") },
      { value: "medium", label: t("sev_medium") },
      { value: "high", label: t("sev_high") },
      { value: "critical", label: t("sev_critical") },
    ] },
    { name: "status", label: t("statusLabel"), type: "select", options: [
      { value: "detected", label: t("st_detected") },
      { value: "contained", label: t("st_contained") },
      { value: "recovered", label: t("st_recovered") },
      { value: "closed", label: t("st_closed") },
    ] },
    { name: "impact_category", label: t("impactCategory"), type: "select", options: [
      { value: "availability", label: t("impact_availability") },
      { value: "confidentiality", label: t("impact_confidentiality") },
      { value: "integrity", label: t("impact_integrity") },
      { value: "authenticity", label: t("impact_authenticity") },
    ] },
    { name: "estimated_impact_level", label: t("impactLevel"), type: "number", min: 1, max: 5 },
    { name: "affected_systems", label: t("affectedSystems"), type: "text" },
    { name: "users_affected_count", label: t("affectedUsers"), type: "number", min: 0 },
    { name: "cross_border", label: t("crossBorder"), type: "checkbox" },
    { name: "supply_chain_impact", label: t("supplyChain"), type: "checkbox" },
    { name: "description", label: t("descriptionLabel"), type: "textarea", required: true },
  ]

  const openCreate = () => { setEditing(null); setDialogOpen(true) }
  const openEdit = (inc: any) => { setEditing(inc); setDialogOpen(true) }

  const submit = async (values: EntityValues) => {
    try {
      if (editing) {
        // detected_at is deliberately not patchable: the three Art. 23 deadlines
        // are stored at declaration time, and moving them later would change an
        // obligation the operator may already have acted on.
        await updateIncident.mutateAsync({ id: editing.id, data: values })
        toast.success(t("incidentUpdated"))
      } else {
        await createIncident.mutateAsync(values)
        toast.success(t("incidentCreated"))
      }
      setDialogOpen(false)
    } catch (err: any) {
      toast.error(editing ? t("incidentUpdateFailed") : t("incidentCreateFailed"), { description: err.message })
    }
  }

  const remove = async (inc: any) => {
    if (!window.confirm(tc("confirmDelete"))) return
    try {
      await deleteIncident.mutateAsync(inc.id)
      toast.success(t("incidentDeleted"))
    } catch (err: any) {
      toast.error(t("incidentDeleteFailed"), { description: err.message })
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-2">
          <Siren className="h-6 w-6 text-primary" aria-hidden="true" />
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
        </div>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <div className="flex flex-wrap justify-end gap-2">
        {/* Deliberately the loudest control on the page. It is used during a
            live incident by someone who should not have to look for it. */}
        <Button variant="destructive" onClick={() => setRedButtonOpen(true)}>
          <Siren className="mr-2 h-4 w-4" />
          {t("redButton.open")}
        </Button>
        <Button onClick={openCreate}>
          <Plus className="mr-2 h-4 w-4" />
          {t("declareIncident")}
        </Button>
      </div>

      {/* Summary */}
      <div className="grid gap-4 sm:grid-cols-2 lg:max-w-xl">
        <Card>
          <CardContent className="flex items-center gap-4 py-5">
            <div className="rounded-full bg-primary/10 p-3">
              <Siren className="h-5 w-5 text-primary" aria-hidden="true" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums">{openCount}</p>
              <p className="text-sm text-muted-foreground">{t("openNow")}</p>
            </div>
          </CardContent>
        </Card>
        <Card className={cn(breachedCount > 0 && "border-destructive/40")}>
          <CardContent className="flex items-center gap-4 py-5">
            <div className={cn("rounded-full p-3", breachedCount > 0 ? "bg-destructive/10" : "bg-emerald-500/10")}>
              <AlertOctagon className={cn("h-5 w-5", breachedCount > 0 ? "text-destructive" : "text-emerald-600")} aria-hidden="true" />
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums">{breachedCount}</p>
              <p className="text-sm text-muted-foreground">
                {breachedCount > 0 ? t("atRisk") : t("allClear")}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-20 text-center">
            <div className="rounded-full border border-primary/20 bg-primary/5 p-6 mb-5">
              <ShieldAlert className="h-9 w-9 text-primary opacity-80" aria-hidden="true" />
            </div>
            <h3 className="text-xl font-semibold mb-1.5">{t("noIncidents")}</h3>
            <p className="text-muted-foreground max-w-md">{t("noIncidentsDesc")}</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {items.map((inc) => {
            const detected = new Date(inc.detected_at)
            const dl: Record<string, Deadline> = Object.fromEntries(
              (inc.deadlines as Deadline[]).map((d) => [d.label, d])
            )
            return (
              <Card key={inc.id} className={cn(inc.is_open && inc.severity === "critical" && "border-destructive/30")}>
                <CardHeader className="pb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <CardTitle className="text-base">{inc.title}</CardTitle>
                    <Badge variant={severityVariant[inc.severity] ?? "medium"}>
                      {t(`sev_${inc.severity}`)}
                    </Badge>
                    <Badge variant="outline">{t(`st_${inc.status}`)}</Badge>
                    {inc.supply_chain_impact && (
                      <Badge variant="secondary">Art. 18</Badge>
                    )}
                    <div className="ml-auto flex items-center gap-1">
                      <Button variant="ghost" size="sm" onClick={() => openEdit(inc)} aria-label={tc("edit")} title={tc("edit")}>
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => remove(inc)} aria-label={tc("delete")} title={tc("delete")}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    {t("detected")}: {detected.toLocaleString()}
                    {inc.affected_systems ? ` · ${inc.affected_systems}` : ""}
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-3">
                    <DeadlineChip title={`${t("earlyWarning")} · 24h`} deadline={dl.early_warning} isOpen={inc.is_open} nowMs={nowMs} recording={recordSubmission.isPending} onRecordSent={() => markSubmitted(inc, "early_warning")} />
                    <DeadlineChip title={`${t("notification")} · 72h`} deadline={dl.notification} isOpen={inc.is_open} nowMs={nowMs} recording={recordSubmission.isPending} onRecordSent={() => markSubmitted(inc, "notification")} />
                    {/* Art. 23(4)(d): one month from the submission of the 72-hour
                        notification, not from detection. */}
                    <DeadlineChip title={`${t("finalReport")} · 1M`} deadline={dl.final_report} isOpen={inc.is_open} nowMs={nowMs} recording={recordSubmission.isPending} onRecordSent={() => markSubmitted(inc, "final_report")} />
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}

      <EntityFormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        title={editing ? t("editIncident") : t("declareIncident")}
        description={t("formDescription")}
        fields={fields}
        initialValues={editing ?? undefined}
        submitting={createIncident.isPending || updateIncident.isPending}
        onSubmit={submit}
      />

      <RedButtonDialog open={redButtonOpen} onOpenChange={setRedButtonOpen} />
    </div>
  )
}
