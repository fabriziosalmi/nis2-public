// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// Establishing authority over a scan target.
//
// The platform had no ownership check at all: any authenticated user could add
// any domain — or a /16, which the validator permits — and have the scanner
// port-scan it, attempt zone transfers against its nameservers, and request
// /.env and /.git/HEAD from it. The one control that shipped was a legal
// disclaimer in localStorage on the public landing page, explicitly suppressed
// for logged-in users: shown to people who cannot scan, hidden from those who
// can.
//
// Two paths, because a domain and an address range are not provable the same
// way. A domain gets a DNS TXT challenge — the Let's Encrypt DNS-01 mechanism,
// evidence rather than assertion. An address range has no DNS to prove anything
// with, so what remains is a named, dated, recorded statement. That does not
// stop misuse; it moves the record from "the platform allowed it" to "this
// person asserted it".

"use client"

import { useState } from "react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Loader2, ShieldCheck, Copy, Check } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { api } from "@/lib/api-client"

interface Props {
  asset: any | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onVerified: () => void
}

export function VerifyOwnershipDialog({ asset, open, onOpenChange, onVerified }: Props) {
  const t = useTranslations("assets.verification")
  const tc = useTranslations("common")
  const [loading, setLoading] = useState(false)
  const [challenge, setChallenge] = useState<any | null>(null)
  const [statement, setStatement] = useState("")
  const [copied, setCopied] = useState(false)
  const [lastCheck, setLastCheck] = useState<string | null>(null)

  const isDomain = asset?.target_type === "domain"

  const start = async () => {
    setLoading(true)
    try {
      setChallenge(await api.startAssetVerification(asset.id))
      setLastCheck(null)
    } catch (err: any) {
      toast.error(t("startFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const check = async () => {
    setLoading(true)
    try {
      const res = await api.checkAssetVerification(asset.id)
      setLastCheck(res.detail ?? null)
      if (res.status === "verified") {
        toast.success(t("verified"))
        onVerified()
        onOpenChange(false)
      }
    } catch (err: any) {
      toast.error(t("checkFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const attest = async () => {
    setLoading(true)
    try {
      await api.attestAssetAuthority(asset.id, statement)
      toast.success(t("attested"))
      onVerified()
      onOpenChange(false)
      setStatement("")
    } catch (err: any) {
      toast.error(t("attestFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const copyRecord = async () => {
    try {
      await navigator.clipboard.writeText(challenge.record_value)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error(t("copyFailed"))
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            {t("title")}
          </DialogTitle>
          <DialogDescription>
            {asset ? t("subtitle", { target: asset.target_value }) : ""}
          </DialogDescription>
        </DialogHeader>

        {isDomain ? (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">{t("dnsExplanation")}</p>

            {!challenge ? (
              <Button onClick={start} disabled={loading}>
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("issueChallenge")}
              </Button>
            ) : (
              <div className="space-y-3">
                <div className="space-y-1">
                  <Label>{t("recordName")}</Label>
                  <code className="block break-all rounded bg-muted px-3 py-2 font-mono text-xs">
                    {challenge.record_name}
                  </code>
                </div>
                <div className="space-y-1">
                  <Label>{t("recordValue")}</Label>
                  <div className="flex items-start gap-2">
                    <code className="block flex-1 break-all rounded bg-muted px-3 py-2 font-mono text-xs">
                      {challenge.record_value}
                    </code>
                    <Button type="button" variant="outline" size="sm" onClick={copyRecord}>
                      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    </Button>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">{t("propagationHint")}</p>
                {lastCheck && (
                  <p className="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
                    {lastCheck}
                  </p>
                )}
                <Button onClick={check} disabled={loading}>
                  {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  {t("checkNow")}
                </Button>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            {/* Deliberately blunt. The statement is recorded against the user's
                account and lands in the audit log; they should know that before
                they type it, not afterwards. */}
            <p className="text-sm text-muted-foreground">{t("attestExplanation")}</p>
            <div className="space-y-2">
              <Label htmlFor="attestation">{t("statementLabel")}</Label>
              <textarea
                id="attestation"
                rows={3}
                className="flex w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                value={statement}
                onChange={(e) => setStatement(e.target.value)}
                placeholder={t("statementPlaceholder")}
              />
              <p className="text-xs text-muted-foreground">{t("statementHint")}</p>
            </div>
            <Button onClick={attest} disabled={loading || statement.trim().length < 10}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t("attestAction")}
            </Button>
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{tc("cancel")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
