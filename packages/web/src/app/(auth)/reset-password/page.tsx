// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState, Suspense } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import Link from "next/link"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Loader2, CheckCircle2, AlertCircle } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { api } from "@/lib/api-client"
import { Logo } from "@/components/brand/logo"
import { useDocumentTitle } from "@/hooks/use-document-title"

// Audit B05 — completes the reset flow. Token comes from the URL
// query string (?token=...) of the link in the email.
//
// The API collapses {unknown, expired, used} into a single 400 so
// attackers can't tell which class their token fell into. We mirror
// that here with a single localized error.
//
// On success the API stamps the JWT iat watermark; any old session
// this user had open is now invalid. The user lands at /login and
// signs in fresh — this is the right behavior security-wise even if
// it costs an extra click.
const resetSchema = z
  .object({
    new_password: z.string().min(8, "auth.passwordMin8"),
    confirm_password: z.string().min(1, "auth.passwordRequired"),
  })
  .refine((data) => data.new_password === data.confirm_password, {
    message: "profilePage.passwordsDontMatch",
    path: ["confirm_password"],
  })

type ResetForm = z.infer<typeof resetSchema>

function ResetPasswordInner() {
  const t = useTranslations()
  const router = useRouter()
  const searchParams = useSearchParams()
  const token = searchParams?.get("token") || ""
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("resetPasswordPage.title"))

  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ResetForm>({
    resolver: zodResolver(resetSchema),
  })

  // Surface the missing-token state up front rather than letting the
  // submit go and explode — `?token=` URLs are usually a copy-paste
  // accident.
  if (!token) {
    return (
      <Card>
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <Logo size={40} />
          </div>
          <div className="flex justify-center mb-2">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
              <AlertCircle className="h-6 w-6 text-destructive" />
            </div>
          </div>
          <CardTitle className="text-2xl">{t("resetPasswordPage.invalidLinkTitle")}</CardTitle>
          <CardDescription>{t("resetPasswordPage.invalidLinkDescription")}</CardDescription>
        </CardHeader>
        <CardFooter className="flex flex-col gap-4">
          <Button asChild className="w-full">
            <Link href="/forgot-password">{t("resetPasswordPage.requestNewLink")}</Link>
          </Button>
        </CardFooter>
      </Card>
    )
  }

  const onSubmit = async (data: ResetForm) => {
    setLoading(true)
    setSubmitError(null)
    try {
      await api.resetPassword(token, data.new_password)
      setDone(true)
      toast.success(t("resetPasswordPage.success"))
      // Brief pause so the user sees the success state before we
      // bounce them to /login.
      setTimeout(() => router.push("/login"), 1500)
    } catch (err: any) {
      // Single error bucket — see comment at top.
      setSubmitError(t("resetPasswordPage.invalidOrExpired"))
    } finally {
      setLoading(false)
    }
  }

  if (done) {
    return (
      <Card>
        <CardHeader className="space-y-1 text-center">
          <div className="flex justify-center mb-2">
            <Logo size={40} />
          </div>
          <div className="flex justify-center mb-2">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-500/10">
              <CheckCircle2 className="h-6 w-6 text-green-600" />
            </div>
          </div>
          <CardTitle className="text-2xl">{t("resetPasswordPage.successTitle")}</CardTitle>
          <CardDescription>{t("resetPasswordPage.successDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-center text-xs text-muted-foreground">
            {t("resetPasswordPage.redirecting")}
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="space-y-1 text-center">
        <div className="flex justify-center mb-2">
          <Logo size={40} />
        </div>
        <CardTitle className="text-2xl">{t("resetPasswordPage.title")}</CardTitle>
        <CardDescription>{t("resetPasswordPage.description")}</CardDescription>
      </CardHeader>
      {/* method="post": a pre-hydration native submit must POST, not leak the new password via a GET URL. */}
      <form method="post" onSubmit={handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          {submitError && (
            <div className="rounded-lg border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {submitError}
            </div>
          )}
          <div className="space-y-2">
            <Label htmlFor="new_password">{t("resetPasswordPage.newPassword")}</Label>
            <Input
              id="new_password"
              type="password"
              placeholder={t("auth.passwordMin8")}
              autoFocus
              {...register("new_password")}
            />
            {errors.new_password && (
              <p className="text-xs text-destructive">{t(errors.new_password.message as any)}</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm_password">{t("resetPasswordPage.confirmPassword")}</Label>
            <Input
              id="confirm_password"
              type="password"
              {...register("confirm_password")}
            />
            {errors.confirm_password && (
              <p className="text-xs text-destructive">{t(errors.confirm_password.message as any)}</p>
            )}
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t("resetPasswordPage.submit")}
          </Button>
          <p className="text-center text-sm text-muted-foreground">
            <Link href="/login" className="font-medium text-primary hover:underline">
              {t("resetPasswordPage.backToLogin")}
            </Link>
          </p>
        </CardFooter>
      </form>
    </Card>
  )
}

// useSearchParams() requires a Suspense boundary in the Next.js App
// Router (the framework hydrates query params on the client; the
// build fails if the consumer isn't wrapped). The fallback is the
// same card chrome, so the layout doesn't jump.
export default function ResetPasswordPage() {
  return (
    <Suspense
      fallback={
        <Card>
          <CardHeader>
            <CardTitle className="text-2xl text-center">…</CardTitle>
          </CardHeader>
        </Card>
      }
    >
      <ResetPasswordInner />
    </Suspense>
  )
}
