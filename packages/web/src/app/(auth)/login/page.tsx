// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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
      const res = await api.login(data.email, data.password)
      setAuth(res.user, res.org_id || null)
      router.push("/dashboard")
    } catch (err: any) {
      toast.error(t("auth.loginFailed"), { description: err.message || t("auth.invalidCredentials") })
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
      <form onSubmit={handleSubmit(onSubmit)}>
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
              {...register("password")}
            />
            {errors.password && (
              <p id="password-error" className="text-xs text-destructive">
                {t(errors.password.message as any)}
              </p>
            )}
          </div>
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
