// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import Link from "next/link"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Loader2, Mail } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { api } from "@/lib/api-client"
import { Logo } from "@/components/brand/logo"
import { useDocumentTitle } from "@/hooks/use-document-title"

// Audit B05 — entry point of the password-reset flow.
//
// Critical UX invariant: success and "email-not-on-file" must look
// identical. The API returns 204 either way; we mirror that here by
// flipping to the same confirmation card on every submit. If we
// branched on an error, this page would become a free email-enumeration
// oracle (the precise bug we're closing).
//
// Zod messages are i18n keys resolved via t(...) — same pattern as
// login/register.
const forgotSchema = z.object({
  email: z.string().email("auth.invalidEmail"),
})

type ForgotForm = z.infer<typeof forgotSchema>

export default function ForgotPasswordPage() {
  const t = useTranslations()
  const [loading, setLoading] = useState(false)
  const [submitted, setSubmitted] = useState(false)
  const [submittedEmail, setSubmittedEmail] = useState("")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("forgotPasswordPage.title"))

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ForgotForm>({
    resolver: zodResolver(forgotSchema),
  })

  const onSubmit = async (data: ForgotForm) => {
    setLoading(true)
    try {
      await api.forgotPassword(data.email)
    } catch {
      // Per the security note above: never surface the failure to the
      // user. The most likely "error" is a 429 from the rate limiter,
      // and even that we treat as success — the legitimate user can
      // just retry in a minute.
    } finally {
      setSubmittedEmail(data.email)
      setSubmitted(true)
      setLoading(false)
    }
  }

  if (submitted) {
    return (
      <Card>
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <Logo size={40} />
          </div>
          <div className="flex justify-center mb-2">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <Mail className="h-6 w-6 text-primary" />
            </div>
          </div>
          <CardTitle className="text-2xl">{t("forgotPasswordPage.successTitle")}</CardTitle>
          <CardDescription>
            {t("forgotPasswordPage.successDescription", { email: submittedEmail })}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-center text-xs text-muted-foreground">
            {t("forgotPasswordPage.checkSpam")}
          </p>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button asChild variant="outline" className="w-full">
            <Link href="/login">{t("forgotPasswordPage.backToLogin")}</Link>
          </Button>
        </CardFooter>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <Logo size={40} />
        </div>
        <CardTitle className="text-2xl">{t("forgotPasswordPage.title")}</CardTitle>
        <CardDescription>{t("forgotPasswordPage.description")}</CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">{t("auth.email")}</Label>
            <Input
              id="email"
              type="email"
              placeholder={t("auth.emailPlaceholder")}
              autoFocus
              {...register("email")}
            />
            {errors.email && <p className="text-xs text-destructive">{t(errors.email.message as any)}</p>}
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t("forgotPasswordPage.submit")}
          </Button>
          <p className="text-center text-sm text-muted-foreground">
            <Link href="/login" className="font-medium text-primary hover:underline">
              {t("forgotPasswordPage.backToLogin")}
            </Link>
          </p>
        </CardFooter>
      </form>
    </Card>
  )
}
