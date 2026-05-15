// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Loader2, ArrowLeft } from "lucide-react"
import Link from "next/link"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select as UISelect, SelectContent, SelectItem, SelectTrigger as UISelectTrigger, SelectValue,
} from "@/components/ui/select"
import { useCreateScan } from "@/hooks/use-scans"
import { useAssets, useCreateAsset } from "@/hooks/use-assets"
import { useDocumentTitle } from "@/hooks/use-document-title"

// Field names MUST match the backend schema (packages/api/app/schemas/scan.py:ScanCreate
// + packages/api/app/routers/scans.py create_scan default features). Pydantic
// silently drops unknown fields, so a typo here = silent default-override at
// the API and a confusing user experience (the user thinks they disabled
// port_scan; the API enables it; the scan task crashes downstream looking
// for `dns_checks` that aren't there). Reported by Davide
//
// The validation messages below are i18n KEYS, not literal strings — they
// resolve to the `scansNewPage` namespace via t(error.message) at render
// time (zod is initialised before useTranslations is available, same
// pattern as login/register).
const scanSchema = z.object({
  name: z.string().min(1, "nameRequired"),
  scan_type: z.enum(["full", "quick", "custom"]),
  features: z.object({
    dns_checks: z.boolean(),
    web_checks: z.boolean(),
    port_scan: z.boolean(),
    whois_checks: z.boolean(),
  }),
  // Per-host scan timeout. Backend enforces 1..120 (see ScanCreate); we
  // mirror the bounds in the FE so zod catches bad input before a round-trip.
  scan_timeout: z.number().min(1).max(120).optional(),
  concurrency: z.number().min(1).max(200).optional(),
  max_hosts: z.number().min(0).max(100000).optional(),
})

type ScanForm = z.infer<typeof scanSchema>

// Note: previously this file shipped a `sampleAssets` placeholder list used
// when the assets API hadn't loaded yet. That gave users the (fake) ability
// to "select" an asset with id="1", which then 400'd on submit because no
// such Asset exists in the org's DB. Removed in v2.4.11 — show an empty
// state instead, with a CTA to add real assets.
//
// v2.4.15 audit B-DRA-04: this page used to render every label, button
// and toast in hardcoded English. Wired up to the new `scansNewPage`
// i18n namespace below.
export default function NewScanPage() {
  const t = useTranslations("scansNewPage")
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const router = useRouter()
  const createScan = useCreateScan()
  const createAsset = useCreateAsset()
  const { data: assetsData } = useAssets()
  const assets = assetsData?.items || []
  const [selectedAssets, setSelectedAssets] = useState<string[]>([])
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [isAssetDialogOpen, setIsAssetDialogOpen] = useState(false)

  const {
    register: registerAsset,
    handleSubmit: handleAssetSubmit,
    reset: resetAsset,
    setValue: setAssetValue,
    formState: { errors: assetErrors },
  } = useForm({
    resolver: zodResolver(
      z.object({
        name: z.string().min(1, "Name is required"),
        type: z.string().min(1, "Type is required"),
        target: z.string().min(1, "Target is required"),
      })
    ),
    defaultValues: { name: "", type: "domain", target: "" }
  })

  const onAssetSubmit = async (data: any) => {
    try {
      const newAsset = await createAsset.mutateAsync({
        name: data.name,
        target_type: data.type,
        target_value: data.target,
        tags: [],
      } as any)
      toast.success(tc("success"))
      setIsAssetDialogOpen(false)
      resetAsset()
      // Automatically select the newly created asset
      if (newAsset?.id) {
        setSelectedAssets((prev) => [...prev, newAsset.id])
      }
    } catch (err: any) {
      toast.error(tc("error"), { description: err.message })
    }
  }

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<ScanForm>({
    resolver: zodResolver(scanSchema),
    defaultValues: {
      scan_type: "full",
      features: { dns_checks: true, web_checks: true, port_scan: true, whois_checks: true },
      scan_timeout: 10,   // backend max is 120s/host
      concurrency: 20,
      max_hosts: 100,
    },
  })

  const features = watch("features")
  const scanType = watch("scan_type")

  const toggleAsset = (id: string) => {
    setSelectedAssets((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id]
    )
  }

  const onSubmit = async (data: ScanForm) => {
    if (selectedAssets.length === 0) {
      toast.error(t("selectAssetError"))
      return
    }
    try {
      const result = await createScan.mutateAsync({
        ...data,
        asset_ids: selectedAssets,
      })
      toast.success(t("scanCreated"))
      router.push(`/dashboard/scans/${result.id}`)
    } catch (err: any) {
      toast.error(t("scanCreateFailed"), { description: err.message })
    }
  }

  // Centralised feature catalogue. Bumping a key here automatically
  // surfaces the new feature in the UI; the labels and hints come
  // from the i18n bundle so the same row localises across all 5
  // locales without code changes.
  const featureRows = [
    { key: "dns_checks" as const, label: t("featureDnsLabel"), hint: t("featureDnsHint") },
    { key: "web_checks" as const, label: t("featureWebLabel"), hint: t("featureWebHint") },
    { key: "port_scan" as const, label: t("featurePortsLabel"), hint: t("featurePortsHint") },
    { key: "whois_checks" as const, label: t("featureWhoisLabel"), hint: t("featureWhoisHint") },
  ]

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link href="/dashboard/scans">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Basic info */}
        <Card>
          <CardHeader>
            <CardTitle>{t("detailsTitle")}</CardTitle>
            <CardDescription>{t("detailsDescription")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">{t("scanNameLabel")}</Label>
              <Input id="name" placeholder={t("scanNamePlaceholder")} {...register("name")} />
              {errors.name && <p className="text-xs text-destructive">{t(errors.name.message as any)}</p>}
            </div>

            <div className="space-y-2">
              <Label>{t("scanTypeLabel")}</Label>
              <div className="grid grid-cols-3 gap-3">
                {(["full", "quick", "custom"] as const).map((type) => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => setValue("scan_type", type)}
                    className={`rounded-lg border p-3 text-center text-sm font-medium transition-colors ${
                      scanType === type
                        ? "border-primary bg-primary/5 text-primary"
                        : "border-input hover:border-primary/50"
                    }`}
                  >
                    <span>{t(`scanType${type.charAt(0).toUpperCase()}${type.slice(1)}` as any)}</span>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {t(`scanType${type.charAt(0).toUpperCase()}${type.slice(1)}Hint` as any)}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Assets */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle>{t("assetsTitle")}</CardTitle>
              <CardDescription>{t("assetsDescription")}</CardDescription>
            </div>
            <Dialog open={isAssetDialogOpen} onOpenChange={setIsAssetDialogOpen}>
              <DialogTrigger asChild>
                <Button type="button" variant="outline" size="sm">
                  {t("manageAssets", { defaultValue: "Add Asset" })}
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>{t("manageAssets", { defaultValue: "Add Asset" })}</DialogTitle>
                  <DialogDescription>
                    Create a new asset to scan without leaving this page.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label>Name</Label>
                    <Input placeholder="E.g., Production API" {...registerAsset("name")} />
                    {assetErrors.name && <p className="text-xs text-destructive">{assetErrors.name.message as string}</p>}
                  </div>
                  <div className="space-y-2">
                    <Label>Type</Label>
                    <UISelect onValueChange={(v) => setAssetValue("type", v)} defaultValue="domain">
                      <UISelectTrigger>
                        <SelectValue placeholder="Select type" />
                      </UISelectTrigger>
                      <SelectContent>
                        <SelectItem value="domain">Domain</SelectItem>
                        <SelectItem value="ip">IP Address</SelectItem>
                        <SelectItem value="cidr">CIDR Block</SelectItem>
                      </SelectContent>
                    </UISelect>
                  </div>
                  <div className="space-y-2">
                    <Label>Target</Label>
                    <Input placeholder="api.example.com" {...registerAsset("target")} />
                    {assetErrors.target && <p className="text-xs text-destructive">{assetErrors.target.message as string}</p>}
                  </div>
                </div>
                <DialogFooter>
                  <Button type="button" variant="outline" onClick={() => setIsAssetDialogOpen(false)}>Cancel</Button>
                  <Button type="button" onClick={handleAssetSubmit(onAssetSubmit)} disabled={createAsset.isPending}>
                    {createAsset.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Save
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </CardHeader>
          <CardContent>
            {assets.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-8 text-center bg-muted/30">
                <p className="text-sm font-medium">{t("noAssetsTitle")}</p>
                <p className="text-xs text-muted-foreground mt-1 mb-4">
                  {t("noAssetsDescription")}
                </p>
                <Button type="button" variant="outline" size="sm" onClick={() => setIsAssetDialogOpen(true)}>
                  Create your first asset
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {assets.map((asset: any) => {
                  const isSelected = selectedAssets.includes(asset.id);
                  return (
                    <label
                      key={asset.id}
                      className={`relative flex items-center gap-4 rounded-xl border p-4 cursor-pointer transition-all duration-200 ${
                        isSelected
                          ? "border-primary bg-primary/5 shadow-md shadow-primary/10"
                          : "border-input bg-card hover:border-primary/40 hover:bg-muted/50"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleAsset(asset.id)}
                        className="sr-only"
                      />
                      <div className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border ${
                        isSelected ? "bg-primary border-primary" : "border-muted-foreground/30 bg-transparent"
                      }`}>
                        {isSelected && (
                          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary-foreground" />
                          </svg>
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm font-semibold truncate ${isSelected ? "text-primary" : "text-foreground"}`}>{asset.name}</p>
                        <p className="text-xs text-muted-foreground truncate">{asset.target_value}</p>
                      </div>
                      <Badge variant={isSelected ? "default" : "secondary"} className="shrink-0 text-[10px] px-1.5 h-5">
                        {asset.target_type.toUpperCase()}
                      </Badge>
                    </label>
                  )
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Feature toggles */}
        <Card>
          <CardHeader>
            <CardTitle>{t("featuresTitle")}</CardTitle>
            <CardDescription>{t("featuresDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              {featureRows.map(({ key, label, hint }) => {
                const isSelected = features[key];
                return (
                  <label
                    key={key}
                    className={`relative flex items-start gap-4 rounded-xl border p-4 cursor-pointer transition-all duration-200 ${
                      isSelected
                        ? "border-primary bg-primary/5 shadow-md shadow-primary/10 scale-[1.02]"
                        : "border-input bg-card hover:border-primary/40 hover:bg-muted/50"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={(e) => setValue(`features.${key}`, e.target.checked)}
                      className="sr-only"
                    />
                    <div className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border ${
                      isSelected ? "bg-primary border-primary" : "border-muted-foreground/30 bg-transparent"
                    }`}>
                      {isSelected && (
                        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                          <path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-primary-foreground" />
                        </svg>
                      )}
                    </div>
                    <div>
                      <p className={`text-sm font-semibold ${isSelected ? "text-primary" : "text-foreground"}`}>{label}</p>
                      <p className="text-xs text-muted-foreground mt-1">{hint}</p>
                    </div>
                  </label>
                )
              })}
            </div>
          </CardContent>
        </Card>

        {/* Advanced settings */}
        <Card>
          <CardHeader>
            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex w-full items-center justify-between"
            >
              <div className="text-left">
                <CardTitle>{t("advancedTitle")}</CardTitle>
                <CardDescription>{t("advancedDescription")}</CardDescription>
              </div>
              <span className="text-sm text-muted-foreground">{showAdvanced ? t("hide") : t("show")}</span>
            </button>
          </CardHeader>
          {showAdvanced && (
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="scan_timeout">{t("timeoutLabel")}</Label>
                  <Input
                    id="scan_timeout"
                    type="number"
                    {...register("scan_timeout", { valueAsNumber: true })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="concurrency">{t("concurrencyLabel")}</Label>
                  <Input
                    id="concurrency"
                    type="number"
                    {...register("concurrency", { valueAsNumber: true })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="max_hosts">{t("maxHostsLabel")}</Label>
                  <Input
                    id="max_hosts"
                    type="number"
                    {...register("max_hosts", { valueAsNumber: true })}
                  />
                </div>
              </div>
            </CardContent>
          )}
        </Card>

        {/* Submit */}
        <div className="flex justify-end gap-3">
          <Button variant="outline" asChild>
            <Link href="/dashboard/scans">{tc("cancel")}</Link>
          </Button>
          <Button type="submit" disabled={createScan.isPending}>
            {createScan.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t("startScan")}
          </Button>
        </div>
      </form>
    </div>
  )
}
