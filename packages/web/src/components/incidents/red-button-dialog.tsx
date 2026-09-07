// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// The CSIRT "Red Button" — Art. 23 Early Warning under duress.
//
// Three questions, because this screen is used at 3 AM during a ransomware
// event by someone who has been awake for nineteen hours. Everything else the
// Early Warning needs is taken from the organisation record and the current
// asset inventory.
//
// The endpoint behind it existed and had no UI, which was the smaller half of
// the problem. The larger half: it composed the payload and persisted nothing.
// No incident row, so no countdown, no 24-hour alert, nothing in the dossier
// and nothing for an auditor — the operator pressed the emergency button, was
// handed a document, and the deadline monitor never learned the incident had
// happened. Declaring is now part of pressing it, so the dialog can promise
// that the clock is running and be telling the truth.
//
// Submission itself stays manual. CSIRT Italia has no API to submit to, and
// the dialog says so rather than implying the filing is done.

"use client"

import { useState } from "react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Siren, Loader2, Download, Copy, Check, ExternalLink } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useCsirtEmergency } from "@/hooks/use-incidents"
import { errorMessage } from "@/lib/utils"

/** The Art. 23 Early Warning document returned by POST /csirt/emergency.
 *  Only the fields this dialog reads are named; the rest is passed through to
 *  the file the operator submits. */
interface EarlyWarningPayload {
  incident: {
    incident_id: string
    early_warning_deadline: string
    notification_deadline: string
  }
  [key: string]: unknown
}

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function RedButtonDialog({ open, onOpenChange }: Props) {
  const t = useTranslations("incidents.redButton")
  const tc = useTranslations("common")
  const emergency = useCsirtEmergency()

  const [whatHappened, setWhatHappened] = useState("")
  const [affectedServices, setAffectedServices] = useState("")
  const [usersAffected, setUsersAffected] = useState("")
  const [payload, setPayload] = useState<EarlyWarningPayload | null>(null)
  const [copied, setCopied] = useState(false)

  const reset = () => {
    setWhatHappened("")
    setAffectedServices("")
    setUsersAffected("")
    setPayload(null)
    setCopied(false)
  }

  const close = (next: boolean) => {
    if (!next) reset()
    onOpenChange(next)
  }

  const declare = async () => {
    try {
      const parsed = parseInt(usersAffected, 10)
      const result = await emergency.mutateAsync({
        what_happened: whatHappened.trim(),
        affected_services: affectedServices.trim(),
        is_ongoing: true,
        estimated_users_affected: Number.isFinite(parsed) ? parsed : null,
      })
      setPayload(result)
      toast.success(t("declared"))
    } catch (err: unknown) {
      toast.error(t("failed"), { description: errorMessage(err) })
    }
  }

  const download = () => {
    // A Blob rather than a data: URI — the payload carries the asset inventory
    // and can be large enough to hit URL length limits in some browsers.
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `early-warning-${payload?.incident.incident_id ?? "incident"}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error(t("copyFailed"))
    }
  }

  const ready = whatHappened.trim().length >= 10 && affectedServices.trim().length > 0

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-destructive">
            <Siren className="h-5 w-5" />
            {t("title")}
          </DialogTitle>
          <DialogDescription>{t("subtitle")}</DialogDescription>
        </DialogHeader>

        {!payload ? (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="what-happened">{t("whatHappened")}</Label>
              <textarea
                id="what-happened"
                rows={3}
                autoFocus
                className="flex w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                value={whatHappened}
                onChange={(e) => setWhatHappened(e.target.value)}
                placeholder={t("whatHappenedPlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="affected-services">{t("affectedServices")}</Label>
              <Input
                id="affected-services"
                value={affectedServices}
                onChange={(e) => setAffectedServices(e.target.value)}
                placeholder={t("affectedServicesPlaceholder")}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="users-affected">{t("usersAffected")}</Label>
              <Input
                id="users-affected"
                type="number"
                min={0}
                value={usersAffected}
                onChange={(e) => setUsersAffected(e.target.value)}
                placeholder={t("usersAffectedPlaceholder")}
              />
            </div>
            {/* Said before the button is pressed, not after: declaring starts a
                legal clock and creates an auditable record. */}
            <p className="rounded border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-muted-foreground">
              {t("consequence")}
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="rounded border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-400">
              {t("clockStarted")}
            </p>
            <div className="space-y-1">
              <Label>{t("earlyWarningDeadline")}</Label>
              <p className="font-mono text-sm">
                {new Date(payload.incident.early_warning_deadline).toLocaleString()}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={download} variant="outline" size="sm">
                <Download className="mr-2 h-4 w-4" />
                {t("downloadPayload")}
              </Button>
              <Button onClick={copy} variant="outline" size="sm">
                {copied ? <Check className="mr-2 h-4 w-4" /> : <Copy className="mr-2 h-4 w-4" />}
                {t("copyPayload")}
              </Button>
              <Button asChild variant="outline" size="sm">
                <a href="https://www.csirt.gov.it/" target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="mr-2 h-4 w-4" />
                  {t("openCsirt")}
                </a>
              </Button>
            </div>
            {/* The platform cannot submit for them and does not pretend to. */}
            <p className="text-xs text-muted-foreground">{t("manualSubmission")}</p>
          </div>
        )}

        <DialogFooter>
          {!payload ? (
            <>
              <Button variant="ghost" onClick={() => close(false)}>{tc("cancel")}</Button>
              <Button variant="destructive" onClick={declare} disabled={!ready || emergency.isPending}>
                {emergency.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("declareAction")}
              </Button>
            </>
          ) : (
            <Button onClick={() => close(false)}>{tc("close")}</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
