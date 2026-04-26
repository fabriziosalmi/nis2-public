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

const scanSchema = z.object({
  name: z.string().min(1, "Scan name is required"),
  scan_type: z.enum(["full", "quick", "custom"]),
  features: z.object({
    dns: z.boolean(),
    web: z.boolean(),
    ports: z.boolean(),
    whois: z.boolean(),
  }),
  timeout: z.number().min(30).max(3600).optional(),
  concurrency: z.number().min(1).max(50).optional(),
  max_hosts: z.number().min(1).max(1000).optional(),
})

type ScanForm = z.infer<typeof scanSchema>

const sampleAssets = [
  { id: "1", name: "Production Web Server", target: "prod.example.com" },
  { id: "2", name: "Staging Environment", target: "staging.example.com" },
  { id: "3", name: "API Gateway", target: "api.example.com" },
  { id: "4", name: "Mail Server", target: "mail.example.com" },
  { id: "5", name: "CDN Endpoint", target: "cdn.example.com" },
]

export default function NewScanPage() {
  const router = useRouter()
  const createScan = useCreateScan()
  const { data: assetsData } = useAssets()
  const assets = assetsData?.items || sampleAssets
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
      features: { dns: true, web: true, ports: true, whois: true },
      timeout: 300,
      concurrency: 10,
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
                    <p className="text-xs text-muted-foreground">{asset.target}</p>
                  </div>
                </label>
              ))}
            </div>
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
              {(["dns", "web", "ports", "whois"] as const).map((feature) => (
                <label
                  key={feature}
                  className="flex items-center gap-3 rounded-lg border p-3 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={features[feature]}
                    onChange={(e) => setValue(`features.${feature}`, e.target.checked)}
                    className="h-4 w-4 rounded border-input"
                  />
                  <div>
                    <p className="text-sm font-medium uppercase">{feature}</p>
                    <p className="text-xs text-muted-foreground">
                      {feature === "dns" && "DNS record analysis"}
                      {feature === "web" && "Web security headers & TLS"}
                      {feature === "ports" && "Open port scanning"}
                      {feature === "whois" && "Domain registration data"}
                    </p>
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
                  <Label htmlFor="timeout">Timeout (seconds)</Label>
                  <Input
                    id="timeout"
                    type="number"
                    {...register("timeout", { valueAsNumber: true })}
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
