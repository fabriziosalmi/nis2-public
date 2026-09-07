// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// TOTP multi-factor authentication, from the profile page.
//
// NIS2 Art. 21(2)(j) names multi-factor authentication explicitly, and the
// three endpoints behind this card (`/auth/totp/setup|verify|disable`) have
// existed and been unit-tested since v2.5.11. What did not exist was any way to
// reach them: no component, and not one of the 945 translation keys mentioned
// TOTP, MFA or 2FA. Enrolment was possible only by calling the API by hand —
// and doing so locked the user out of the dashboard entirely, because the login
// page ignored the {mfa_required: true} response and `/totp/disable` needs the
// session the user could no longer obtain.
//
// Enrolment is deliberately three explicit steps: reveal the secret, confirm a
// generated code, then store the recovery codes. The API only returns the
// recovery codes ONCE, on successful verify, so the UI must not let the user
// navigate away from them by accident.

"use client"

import { useEffect, useState } from "react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Loader2, ShieldCheck, ShieldOff, Copy, Check } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { api } from "@/lib/api-client"

type Stage = "idle" | "enrolling" | "recovery"

export function MfaCard() {
  const t = useTranslations("profilePage.mfa")
  const [stage, setStage] = useState<Stage>("idle")
  const [loading, setLoading] = useState(false)
  // Read the live value rather than the auth store's copy. The store is
  // populated at login and never refreshed, so after enrolling it would keep
  // reporting MFA off and this card would offer enrolment again — issuing a
  // second secret and invalidating the authenticator the user had just set up.
  const [isEnabled, setIsEnabled] = useState(false)

  const [secret, setSecret] = useState("")
  const [code, setCode] = useState("")
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const [disablePassword, setDisablePassword] = useState("")
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    api
      .getMe()
      .then((me: any) => setIsEnabled(!!me?.totp_enabled))
      .catch(() => {
        // Non-fatal: the card renders in its "not enrolled" shape. Enrolment
        // itself would still fail loudly if the account already has MFA.
      })
  }, [])

  const beginEnrolment = async () => {
    setLoading(true)
    try {
      const res = await api.totpSetup()
      setSecret(res.secret)
      setStage("enrolling")
    } catch (err: any) {
      toast.error(t("setupFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const confirmEnrolment = async () => {
    setLoading(true)
    try {
      const res = await api.totpVerify(code)
      // The recovery codes are shown exactly once. Hold the user on this step
      // until they acknowledge; losing them plus losing the authenticator means
      // an administrator has to intervene at the database.
      setRecoveryCodes(res.recovery_codes ?? [])
      setIsEnabled(true)
      setStage("recovery")
      setCode("")
    } catch (err: any) {
      toast.error(t("verifyFailed"), { description: err.message })
      setCode("")
    } finally {
      setLoading(false)
    }
  }

  const disable = async () => {
    setLoading(true)
    try {
      await api.totpDisable(disablePassword)
      setIsEnabled(false)
      setStage("idle")
      setDisablePassword("")
      toast.success(t("disabled"))
    } catch (err: any) {
      toast.error(t("disableFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const copyRecovery = async () => {
    try {
      await navigator.clipboard.writeText(recoveryCodes.join("\n"))
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      toast.error(t("copyFailed"))
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {isEnabled ? <ShieldCheck className="h-5 w-5 text-emerald-600" /> : <ShieldOff className="h-5 w-5" />}
          {t("title")}
        </CardTitle>
        <CardDescription>{isEnabled ? t("enabledDescription") : t("description")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {stage === "recovery" && (
          <div className="space-y-3 rounded-lg border border-amber-300 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950">
            <p className="text-sm font-medium text-amber-900 dark:text-amber-200">{t("recoveryTitle")}</p>
            <p className="text-xs text-amber-900 dark:text-amber-200">{t("recoveryWarning")}</p>
            <ul className="grid grid-cols-2 gap-1 font-mono text-xs" aria-label={t("recoveryTitle")}>
              {recoveryCodes.map((c) => (
                <li key={c} className="rounded bg-background px-2 py-1">{c}</li>
              ))}
            </ul>
            <div className="flex gap-2">
              <Button type="button" variant="outline" size="sm" onClick={copyRecovery}>
                {copied ? <Check className="mr-2 h-3 w-3" /> : <Copy className="mr-2 h-3 w-3" />}
                {t("copyCodes")}
              </Button>
              <Button type="button" size="sm" onClick={() => setStage("idle")}>{t("recoveryStored")}</Button>
            </div>
          </div>
        )}

        {stage === "enrolling" && (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t("secretLabel")}</Label>
              {/* The secret is shown as text rather than a QR code so the card
                  pulls in no image or QR dependency, and so it can be typed into
                  a hardware authenticator or a password manager by hand. */}
              <code className="block break-all rounded bg-muted px-3 py-2 font-mono text-sm">{secret}</code>
              <p className="text-xs text-muted-foreground">{t("secretHint")}</p>
            </div>
            <Separator />
            <div className="space-y-2">
              <Label htmlFor="mfa-confirm">{t("confirmLabel")}</Label>
              <Input
                id="mfa-confirm"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                value={code}
                onChange={(e) => setCode(e.target.value.trim())}
                placeholder={t("confirmPlaceholder")}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="ghost" onClick={() => { setStage("idle"); setCode("") }}>
                {t("cancel")}
              </Button>
              <Button type="button" onClick={confirmEnrolment} disabled={loading || code.length < 6}>
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("confirm")}
              </Button>
            </div>
          </div>
        )}

        {stage === "idle" && !isEnabled && (
          <div className="flex justify-end">
            <Button type="button" onClick={beginEnrolment} disabled={loading}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t("enable")}
            </Button>
          </div>
        )}

        {stage === "idle" && isEnabled && (
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="mfa-disable-pw">{t("disablePasswordLabel")}</Label>
              <Input
                id="mfa-disable-pw"
                type="password"
                autoComplete="current-password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">{t("disableHint")}</p>
            </div>
            <div className="flex justify-end">
              <Button type="button" variant="destructive" onClick={disable} disabled={loading || !disablePassword}>
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("disable")}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
