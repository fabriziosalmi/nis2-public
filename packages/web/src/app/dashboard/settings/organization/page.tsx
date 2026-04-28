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

const orgSchema = z.object({
  name: z.string().min(1, "Organization name is required").max(256),
})

type OrgForm = z.infer<typeof orgSchema>

export default function OrganizationSettingsPage() {
  const t = useTranslations("organizationPage")
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
      toast.success("Organization updated")
    } catch (err: any) {
      toast.error("Update failed", { description: err.message })
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
            General
          </CardTitle>
          <CardDescription>Basic organization information</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Organization Name</Label>
              <Input id="name" placeholder="Acme Corp" {...register("name")} />
              {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
            </div>

            <div className="space-y-2">
              <Label>Slug</Label>
              <Input value={org?.slug || ""} disabled className="bg-muted" />
              <p className="text-xs text-muted-foreground">URL identifier, auto-generated from name. Cannot be changed.</p>
            </div>

            <div className="space-y-2">
              <Label>Plan</Label>
              <Input value={org?.plan || "free"} disabled className="bg-muted capitalize" />
            </div>

            <div className="space-y-2">
              <Label>Organization ID</Label>
              <Input value={orgId || ""} disabled className="bg-muted font-mono text-xs" />
              <p className="text-xs text-muted-foreground">Use this ID for API integrations</p>
            </div>

            <Separator />

            <div className="flex justify-end">
              <Button type="submit" disabled={loading || !isDirty}>
                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save Changes
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="text-destructive">Danger Zone</CardTitle>
          <CardDescription>Irreversible actions for this organization</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between rounded-lg border border-destructive/30 p-4">
            <div>
              <p className="font-medium">Delete Organization</p>
              <p className="text-sm text-muted-foreground">Permanently delete this organization and all its data</p>
            </div>
            <Button variant="destructive" size="sm" disabled>
              Delete
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
