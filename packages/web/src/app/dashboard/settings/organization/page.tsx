// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Loader2, Building2 } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"
import { useDocumentTitle } from "@/hooks/use-document-title"

// The error message is an i18n KEY resolved via `t(error.message)` at
// render — same pattern as login / register (zod is initialised before
// the translations hook is available, so we can't call `t()` here).
// `t` here is scoped to `organizationPage`, so we pass the bare key.
// v2.4.15: was a hardcoded English literal until the audit caught it.
const orgSchema = z.object({
  name: z.string().min(1, "nameRequired").max(256),
})

type OrgForm = z.infer<typeof orgSchema>

export default function OrganizationSettingsPage() {
  const t = useTranslations("organizationPage")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const orgId = useAuthStore((s) => s.orgId)
  const [loading, setLoading] = useState(false)
  const [org, setOrg] = useState<any>(null)

  const { register, handleSubmit, reset, formState: { errors, isDirty } } = useForm<OrgForm>({
    resolver: zodResolver(orgSchema),
  })

  useEffect(() => {
    if (orgId) {
      api.getOrg(orgId).then((data) => {
        setOrg(data)
        reset({ name: data.name })
      }).catch(() => {})
    }
  }, [orgId, reset])

  const onSubmit = async (data: OrgForm) => {
    if (!orgId) return
    setLoading(true)
    try {
      const updated = await api.updateOrg(orgId, data)
      setOrg(updated)
      reset({ name: updated.name })
      toast.success(t("saved"))
    } catch (err: any) {
      toast.error(t("saveFailed"), { description: err.message })
    } finally {
      setLoading(false)
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
            <Building2 className="h-5 w-5" />
            {t("general")}
          </CardTitle>
          <CardDescription>{t("generalDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">{t("name")}</Label>
              <Input id="name" placeholder={t("namePlaceholder")} {...register("name")} />
              {errors.name && <p className="text-xs text-destructive">{t(errors.name.message as any)}</p>}
            </div>

            <div className="space-y-2">
              <Label>{t("slug")}</Label>
              <Input value={org?.slug || ""} disabled className="bg-muted" />
              <p className="text-xs text-muted-foreground">{t("slugHelp")}</p>
            </div>

            <div className="space-y-2">
              <Label>{t("plan")}</Label>
              <Input value={org?.plan || "free"} disabled className="bg-muted capitalize" />
            </div>

            <div className="space-y-2">
              <Label>{t("orgIdLabel")}</Label>
              <Input value={orgId || ""} disabled className="bg-muted font-mono text-xs" />
              <p className="text-xs text-muted-foreground">{t("orgIdHelp")}</p>
            </div>

            <Separator />

            <div className="flex justify-end">
              <Button type="submit" disabled={loading || !isDirty}>
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {t("save")}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="text-destructive">{t("dangerZone")}</CardTitle>
          <CardDescription>{t("dangerDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border border-destructive/30 p-4">
            <div>
              <p className="font-medium">{t("deleteOrg")}</p>
              <p className="text-sm text-muted-foreground">{t("deleteOrgDescription")}</p>
            </div>
            <Button variant="destructive" size="sm" disabled>
              {t("delete")}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
