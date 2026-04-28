// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Loader2, UserCog, Globe } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"

const profileSchema = z.object({
  full_name: z.string().min(1, "Name is required").max(256),
  locale: z.string().min(2).max(10),
})

// Like elsewhere: zod messages are i18n keys looked up via t() at render.
const passwordSchema = z.object({
  current_password: z.string().min(1, "profilePage.currentPasswordRequired"),
  new_password: z.string().min(8, "auth.passwordMin8"),
  confirm_password: z.string().min(8, "auth.passwordMin8"),
}).refine((data) => data.new_password === data.confirm_password, {
  message: "profilePage.passwordsDontMatch",
  path: ["confirm_password"],
}).refine((data) => data.new_password !== data.current_password, {
  // The backend will also reject this with a 400, but catching it
  // client-side is a kinder UX — no round-trip, error appears under
  // the field that's wrong.
  message: "profilePage.newSameAsCurrent",
  path: ["new_password"],
})

type ProfileForm = z.infer<typeof profileSchema>
type PasswordForm = z.infer<typeof passwordSchema>

const locales = [
  { value: "en", label: "English" },
  { value: "it", label: "Italiano" },
  { value: "de", label: "Deutsch" },
  { value: "fr", label: "Francais" },
  { value: "es", label: "Espanol" },
]

export default function ProfileSettingsPage() {
  const t = useTranslations("profilePage")
  // Top-level translator so zod messages like "auth.passwordMin8" resolve
  // across namespaces. The form-validation errors are stored as i18n
  // *keys* (not messages) — see passwordSchema above.
  const tg = useTranslations()
  const user = useAuthStore((s) => s.user)
  const setAuth = useAuthStore((s) => s.setAuth)
  const orgId = useAuthStore((s) => s.orgId)
  const [loadingProfile, setLoadingProfile] = useState(false)
  const [loadingPassword, setLoadingPassword] = useState(false)

  const profileForm = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues: {
      full_name: user?.full_name || "",
      locale: (user as any)?.locale || "en",
    },
  })

  const passwordForm = useForm<PasswordForm>({
    resolver: zodResolver(passwordSchema),
  })

  const onProfileSubmit = async (data: ProfileForm) => {
    setLoadingProfile(true)
    try {
      const updated = await api.updateMe(data)
      setAuth(updated, orgId)
      profileForm.reset({ full_name: updated.full_name, locale: updated.locale })
      toast.success(t("profileUpdated"))
    } catch (err: any) {
      toast.error(t("updateFailed"), { description: err.message })
    } finally {
      setLoadingProfile(false)
    }
  }

  const onPasswordSubmit = async (data: PasswordForm) => {
    setLoadingPassword(true)
    try {
      // Audit B04: was `api.updateMe(...)`, which dropped the password
      // fields silently and showed a "passwordUpdated" toast that lied.
      // The dedicated endpoint verifies the current password, hashes
      // the new one, and stamps password_changed_at to invalidate other
      // sessions. Cookies for THIS tab are rotated server-side so the
      // user keeps working without a re-login here.
      await api.changePassword({
        current_password: data.current_password,
        new_password: data.new_password,
      })
      passwordForm.reset()
      toast.success(t("passwordUpdated"), { description: t("passwordUpdatedDescription") })
    } catch (err: any) {
      // Match the typical error shapes the backend can produce so the
      // user sees a useful message rather than a generic "update failed".
      const msg = err?.message || ""
      const description = /current password is incorrect/i.test(msg)
        ? t("currentPasswordIncorrect")
        : /must differ/i.test(msg)
          ? t("newSameAsCurrent")
          : msg
      toast.error(t("passwordChangeFailed"), { description })
    } finally {
      setLoadingPassword(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
        <p className="text-muted-foreground">{t("subtitle")}</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserCog className="h-5 w-5" />
            {t("personalInfo")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={profileForm.handleSubmit(onProfileSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">{t("email")}</Label>
              <Input value={user?.email || ""} disabled className="bg-muted" />
            </div>

            <div className="space-y-2">
              <Label htmlFor="full_name">{t("fullName")}</Label>
              <Input id="full_name" {...profileForm.register("full_name")} />
              {profileForm.formState.errors.full_name && (
                <p className="text-xs text-destructive">{profileForm.formState.errors.full_name.message}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="locale" className="flex items-center gap-1">
                <Globe className="h-3.5 w-3.5" />
                {t("locale")}
              </Label>
              <select
                id="locale"
                {...profileForm.register("locale")}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {locales.map((l) => (
                  <option key={l.value} value={l.value}>{l.label}</option>
                ))}
              </select>
            </div>

            <Separator />

            <div className="flex justify-end">
              <Button type="submit" disabled={loadingProfile || !profileForm.formState.isDirty}>
                {loadingProfile && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("saveProfile")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("changePassword")}</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={passwordForm.handleSubmit(onPasswordSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="current_password">{t("currentPassword")}</Label>
              <Input id="current_password" type="password" autoComplete="current-password" {...passwordForm.register("current_password")} />
              {passwordForm.formState.errors.current_password && (
                <p className="text-xs text-destructive">{tg(passwordForm.formState.errors.current_password.message as any)}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="new_password">{t("newPassword")}</Label>
              <Input id="new_password" type="password" autoComplete="new-password" {...passwordForm.register("new_password")} />
              {passwordForm.formState.errors.new_password && (
                <p className="text-xs text-destructive">{tg(passwordForm.formState.errors.new_password.message as any)}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirm_password">{t("confirmNewPassword")}</Label>
              <Input id="confirm_password" type="password" autoComplete="new-password" {...passwordForm.register("confirm_password")} />
              {passwordForm.formState.errors.confirm_password && (
                <p className="text-xs text-destructive">{tg(passwordForm.formState.errors.confirm_password.message as any)}</p>
              )}
            </div>

            <Separator />

            <div className="flex justify-end">
              <Button type="submit" disabled={loadingPassword}>
                {loadingPassword && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("updatePassword")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
