// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useCreateScan } from "@/hooks/use-scans"
import { useAssets } from "@/hooks/use-assets"

// Field names MUST match the backend schema (packages/api/app/schemas/scan.py:ScanCreate
// + packages/api/app/routers/scans.py create_scan default features). Pydantic
// silently drops unknown fields, so a typo here = silent default-override at
// the API and a confusing user experience (the user thinks they disabled
// port_scan; the API enables it; the scan task crashes downstream looking
// for `dns_checks` that aren't there). Reported by Davide F.
const scanSchema = z.object({
  name: z.string().min(1, "Scan name is required"),
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
export default function NewScanPage() {
  const router = useRouter()
  const createScan = useCreateScan()
  const { data: assetsData } = useAssets()
  const assets = assetsData?.items || []
  const [selectedAssets, setSelectedAssets] = useState<string[]>([])
  const [showAdvanced, setShowAdvanced] = useState(false)

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
      toast.error("Please select at least one asset")
      return
    }
    try {
      const result = await createScan.mutateAsync({
        ...data,
        asset_ids: selectedAssets,
      })
      toast.success("Scan created successfully")
      router.push(`/dashboard/scans/${result.id}`)
    } catch (err: any) {
      toast.error("Failed to create scan", { description: err.message })
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link href="/dashboard/scans">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">New Scan</h1>
          <p className="text-muted-foreground">Configure and launch a compliance scan</p>
        </div>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Basic info */}
        <Card>
          <CardHeader>
            <CardTitle>Scan Details</CardTitle>
            <CardDescription>Basic scan configuration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Scan Name</Label>
              <Input id="name" placeholder="e.g., Production Full Scan" {...register("name")} />
              {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
            </div>

            <div className="space-y-2">
              <Label>Scan Type</Label>
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
                    <span className="capitalize">{type}</span>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {type === "full" && "All checks enabled"}
                      {type === "quick" && "Essential checks only"}
                      {type === "custom" && "Choose features"}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Assets */}
        <Card>
          <CardHeader>
            <CardTitle>Target Assets</CardTitle>
            <CardDescription>Select assets to include in the scan</CardDescription>
          </CardHeader>
          <CardContent>
            {assets.length === 0 ? (
              <div className="flex flex-col items-center justify-center rounded-lg border border-dashed py-8 text-center">
                <p className="text-sm font-medium">No assets configured yet</p>
                <p className="text-xs text-muted-foreground mt-1 mb-3">
                  Add at least one domain, IP or CIDR before launching a scan.
                </p>
                <Button variant="outline" size="sm" asChild>
                  <Link href="/dashboard/assets">Manage assets</Link>
                </Button>
              </div>
            ) : (
              <div className="space-y-2">
                {assets.map((asset: any) => (
                  <label
                    key={asset.id}
                    className={`flex items-center gap-3 rounded-lg border p-3 cursor-pointer transition-colors ${
                      selectedAssets.includes(asset.id)
                        ? "border-primary bg-primary/5"
                        : "border-input hover:border-primary/50"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={selectedAssets.includes(asset.id)}
                      onChange={() => toggleAsset(asset.id)}
                      className="h-4 w-4 rounded border-input"
                    />
                    <div>
                      <p className="text-sm font-medium">{asset.name}</p>
                      <p className="text-xs text-muted-foreground">{asset.target_value}</p>
                    </div>
                  </label>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Feature toggles */}
        <Card>
          <CardHeader>
            <CardTitle>Features</CardTitle>
            <CardDescription>Select which checks to run</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              {(
                [
                  ["dns_checks", "DNS", "DNS record analysis"],
                  ["web_checks", "Web", "Web security headers & TLS"],
                  ["port_scan", "Ports", "Open port scanning"],
                  ["whois_checks", "WHOIS", "Domain registration data"],
                ] as const
              ).map(([key, label, hint]) => (
                <label
                  key={key}
                  className="flex items-center gap-3 rounded-lg border p-3 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={features[key]}
                    onChange={(e) => setValue(`features.${key}`, e.target.checked)}
                    className="h-4 w-4 rounded border-input"
                  />
                  <div>
                    <p className="text-sm font-medium">{label}</p>
                    <p className="text-xs text-muted-foreground">{hint}</p>
                  </div>
                </label>
              ))}
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
                <CardTitle>Advanced Settings</CardTitle>
                <CardDescription>Timeout, concurrency, and limits</CardDescription>
              </div>
              <span className="text-sm text-muted-foreground">{showAdvanced ? "Hide" : "Show"}</span>
            </button>
          </CardHeader>
          {showAdvanced && (
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="scan_timeout">Timeout (seconds)</Label>
                  <Input
                    id="scan_timeout"
                    type="number"
                    {...register("scan_timeout", { valueAsNumber: true })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="concurrency">Concurrency</Label>
                  <Input
                    id="concurrency"
                    type="number"
                    {...register("concurrency", { valueAsNumber: true })}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="max_hosts">Max Hosts</Label>
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
            <Link href="/dashboard/scans">Cancel</Link>
          </Button>
          <Button type="submit" disabled={createScan.isPending}>
            {createScan.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Start Scan
          </Button>
        </div>
      </form>
    </div>
  )
}
