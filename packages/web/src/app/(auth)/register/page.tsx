// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
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

// Like login: zod messages are i18n keys resolved via t(...) at render.
const registerSchema = z.object({
  full_name: z.string().min(2, "auth.fullNameRequired"),
  email: z.string().email("auth.invalidEmail"),
  password: z.string().min(8, "auth.passwordMin8"),
  org_name: z.string().min(2, "auth.orgNameRequired"),
})

type RegisterForm = z.infer<typeof registerSchema>

export default function RegisterPage() {
  const t = useTranslations()
  const router = useRouter()
  const setAuth = useAuthStore((s) => s.setAuth)
  const [loading, setLoading] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
  })

  const onSubmit = async (data: RegisterForm) => {
    setLoading(true)
    try {
      const res = await api.register(data)
      setAuth(res.user, res.org_id || null)
      toast.success(t("auth.registerSuccess"))
      router.push("/dashboard")
    } catch (err: any) {
      toast.error(t("auth.registerFailed"), { description: err.message })
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
        <CardTitle className="text-2xl">{t("auth.registerTitle")}</CardTitle>
        <CardDescription>{t("auth.registerDescription")}</CardDescription>
      </CardHeader>
      {/* v2.4.23 audit a11y-14: aria-invalid + aria-describedby on
          every form field so SR users hear validation errors when
          they refocus the offending input. */}
      <form onSubmit={handleSubmit(onSubmit)}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="full_name">{t("auth.fullName")}</Label>
            <Input
              id="full_name"
              placeholder={t("auth.fullNamePlaceholder")}
              aria-invalid={!!errors.full_name}
              aria-describedby={errors.full_name ? "full_name-error" : undefined}
              {...register("full_name")}
            />
            {errors.full_name && (
              <p id="full_name-error" className="text-xs text-destructive">
                {t(errors.full_name.message as any)}
              </p>
            )}
          </div>
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
            <Label htmlFor="password">{t("auth.password")}</Label>
            <Input
              id="password"
              type="password"
              placeholder={t("auth.passwordMin8")}
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
          <div className="space-y-2">
            <Label htmlFor="org_name">{t("auth.orgName")}</Label>
            <Input
              id="org_name"
              placeholder={t("auth.orgNamePlaceholder")}
              aria-invalid={!!errors.org_name}
              aria-describedby={errors.org_name ? "org_name-error" : undefined}
              {...register("org_name")}
            />
            {errors.org_name && (
              <p id="org_name-error" className="text-xs text-destructive">
                {t(errors.org_name.message as any)}
              </p>
            )}
          </div>
        </CardContent>
        <CardFooter className="flex flex-col gap-4">
          <Button type="submit" className="w-full" disabled={loading}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />}
            {t("auth.register")}
          </Button>
          <p className="text-center text-sm text-muted-foreground">
            {t("auth.hasAccount")}{" "}
            <Link href="/login" className="font-medium text-primary hover:underline">
              {t("auth.signIn")}
            </Link>
          </p>
        </CardFooter>
      </form>
    </Card>
  )
}
