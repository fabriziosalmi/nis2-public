// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import Link from "next/link"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Loader2 } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"
import { Logo } from "@/components/brand/logo"
import { useDocumentTitle } from "@/hooks/use-document-title"

// Schema messages stay English here — zod resolves them at form-init time,
// before useTranslations is available. The useTranslations layer below
// re-translates them via the `t(error.message)` lookup (errors are stable
// keys like "auth.invalidEmail" that map into the auth namespace).
const loginSchema = z.object({
  email: z.string().email("auth.invalidEmail"),
  password: z.string().min(1, "auth.passwordRequired"),
})

type LoginForm = z.infer<typeof loginSchema>

export default function LoginPage() {
  const t = useTranslations()
  const router = useRouter()
  // `?session=expired` is set by Providers#SessionExpiredHandler when
  // the api-client gives up on a stale cookie. Showing the banner here
  // (rather than firing the toast that already showed at redirect time)
  // makes the reason visible after the user navigates away from the
  // toast or refreshes /login directly.
  const searchParams = useSearchParams()
  const sessionExpired = searchParams?.get("session") === "expired"
  const setAuth = useAuthStore((s) => s.setAuth)
  const [loading, setLoading] = useState(false)
  // Two-step login state. `mfaRequired` flips after the API answers
  // {mfa_required: true}; the form then shows the code field and resubmits the
  // same credentials with the code attached — there is no separate
  // "complete MFA" endpoint, by design.
  const [mfaRequired, setMfaRequired] = useState(false)
  const [totpCode, setTotpCode] = useState("")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("auth.signIn"))

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginForm>({
    resolver: zodResolver(loginSchema),
  })

  const onSubmit = async (data: LoginForm) => {
    setLoading(true)
    try {
      // The API sets the auth cookies on this response; the body carries
      // the user profile and org id for immediate UI hydration.
      const res = await api.login(data.email, data.password, mfaRequired ? totpCode : undefined)

      // MFA branch. When the account has TOTP enabled and no code was sent,
      // the API answers 200 with {mfa_required: true, partial: true} and sets
      // NO cookie — a success status that is not a session.
      //
      // This branch did not exist. The handler stored res.user (undefined) and
      // pushed to /dashboard, which had no session, 401'd, and bounced back
      // here — an unbreakable loop. Since /auth/totp/disable itself requires a
      // session, anyone who enrolled MFA through the API (the only way, as
      // there was no MFA UI either) was permanently locked out of the web app.
      // Art. 21(2)(j) is specifically about multi-factor authentication, so
      // enabling it must not be the thing that breaks access.
      if (res?.mfa_required) {
        setMfaRequired(true)
        setTotpCode("")
        return
      }

      setAuth(res.user, res.org_id || null)
      router.push("/dashboard")
    } catch (err: any) {
      // A wrong TOTP code comes back as a 401 like a wrong password. Keep the
      // code field on screen so the user can retry without re-typing
      // credentials, and point the message at the code they just entered.
      toast.error(
        mfaRequired ? t("auth.mfaCodeInvalid") : t("auth.loginFailed"),
        { description: mfaRequired ? undefined : err.message || t("auth.invalidCredentials") }
      )
      setTotpCode("")
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card>
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <Logo size={40} />
        </div>
        <CardTitle className="text-2xl">{t("auth.signInTitle")}</CardTitle>
        <CardDescription>{t("auth.signInDescription")}</CardDescription>
      </CardHeader>
      {/* method="post" so a submit BEFORE hydration falls back to POST, not a
          GET that would leak email/password into the URL (logs, history, Referer). */}
      <form method="post" onSubmit={handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          {sessionExpired && (
            <div className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
              {t("auth.sessionExpired")}
            </div>
          )}
          {/* v2.4.23 audit a11y-14 (WCAG SC 3.3.1 Error Identification
              + 1.3.1 Info & Relationships): inline field errors were
              rendered as a styled <p> next to the input, but had no
              programmatic association with the field — SR users
              didn't hear the error when they focused the input.
              aria-describedby links the error to its input, and
              aria-invalid surfaces the validity state. */}
          <div className="space-y-2">
            <Label htmlFor="email">{t("auth.email")}</Label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              placeholder={t("auth.emailPlaceholder")}
              aria-invalid={!!errors.email}
              aria-describedby={errors.email ? "email-error" : undefined}
              {...register("email")}
            />
            {errors.email && (
              <p id="email-error" className="text-xs text-destructive">
                {t(errors.email.message as any)}
              </p>
            )}
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label htmlFor="password">{t("auth.password")}</Label>
              {/* B05 forgot/reset flow: this is the only entry point —
                  putting it next to the password field keeps it discoverable
                  the moment a user starts wondering if they typoed it. */}
              <Link
                href="/forgot-password"
                className="text-xs text-muted-foreground hover:text-primary hover:underline"
              >
                {t("auth.forgotPassword")}
              </Link>
            </div>
            <Input
              id="password"
              type="password"
              placeholder={t("auth.passwordPlaceholder")}
              aria-invalid={!!errors.password}
              aria-describedby={errors.password ? "password-error" : undefined}
              autoComplete="current-password"
              {...register("password")}
            />
            {errors.password && (
              <p id="password-error" className="text-xs text-destructive">
                {t(errors.password.message as any)}
              </p>
            )}
          </div>
          {mfaRequired && (
            <div className="space-y-2">
              <Label htmlFor="totp">{t("auth.mfaCode")}</Label>
              <Input
                id="totp"
                // One-time codes are 6 digits; recovery codes are longer and
                // alphanumeric, and the same field accepts both because the API
                // checks the TOTP first and falls back to the recovery list.
                inputMode="text"
                autoComplete="one-time-code"
                autoFocus
                maxLength={32}
                placeholder={t("auth.mfaCodePlaceholder")}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.trim())}
              />
              <p className="text-xs text-muted-foreground">{t("auth.mfaCodeHint")}</p>
            </div>
          )}
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />}
            {t("auth.signIn")}
          </Button>
          <p className="text-center text-sm text-muted-foreground">
            {t("auth.noAccount")}{" "}
            <Link href="/register" className="font-medium text-primary hover:underline">
              {t("auth.signUp")}
            </Link>
          </p>
        </CardFooter>
      </form>
    </Card>
  )
}
