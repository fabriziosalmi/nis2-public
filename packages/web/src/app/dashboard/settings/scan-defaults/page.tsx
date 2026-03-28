"use client"

import { useState, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Loader2, Radar, Info } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { api } from "@/lib/api-client"
import { useAuthStore } from "@/stores/auth-store"

const scanDefaultsSchema = z.object({
  scan_timeout: z.coerce.number().min(1).max(120),
  concurrency: z.coerce.number().min(1).max(200),
  max_hosts: z.coerce.number().min(0).max(10000),
  dns_checks: z.boolean(),
  web_checks: z.boolean(),
  port_scan: z.boolean(),
  whois_checks: z.boolean(),
})

type ScanDefaultsForm = z.infer<typeof scanDefaultsSchema>

const defaults: ScanDefaultsForm = {
  scan_timeout: 10,
  concurrency: 20,
  max_hosts: 100,
  dns_checks: true,
  web_checks: true,
  port_scan: true,
  whois_checks: true,
}

export default function ScanDefaultsPage() {
  const token = useAuthStore((s) => s.token)
  const orgId = useAuthStore((s) => s.orgId)
  const [loading, setLoading] = useState(false)

  const { register, handleSubmit, reset, formState: { errors, isDirty }, watch } = useForm<ScanDefaultsForm>({
    resolver: zodResolver(scanDefaultsSchema),
    defaultValues: defaults,
  })

  useEffect(() => {
    if (token && orgId) {
      api.getOrg(token, orgId).then((org) => {
        const saved = org.settings?.scan_defaults
        if (saved) reset({ ...defaults, ...saved })
      }).catch(() => {})
    }
  }, [token, orgId, reset])

  const onSubmit = async (data: ScanDefaultsForm) => {
    if (!token || !orgId) return
    setLoading(true)
    try {
      await api.updateOrg(token, orgId, {
        settings: { scan_defaults: data },
      })
      reset(data)
      toast.success("Scan defaults saved")
    } catch (err: any) {
      toast.error("Save failed", { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const ToggleRow = ({ id, label, description }: { id: keyof ScanDefaultsForm; label: string; description: string }) => {
    const val = watch(id)
    return (
      <div className="flex items-center justify-between rounded-lg border p-4">
        <div className="flex-1 mr-4">
          <p className="font-medium">{label}</p>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={!!val}
          onClick={() => setValue(id, !val as any, { shouldDirty: true })}
          className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 ${val ? 'bg-primary' : 'bg-muted'}`}
        >
          <span className={`pointer-events-none block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform duration-200 ${val ? 'translate-x-5' : 'translate-x-0'}`} />
        </button>
        <input type="checkbox" className="sr-only" {...register(id)} />
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Scan Defaults</h1>
        <p className="text-muted-foreground">Configure default settings for new compliance scans</p>
      </div>

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radar className="h-5 w-5" />
              Performance
            </CardTitle>
            <CardDescription>Control scan speed and resource usage</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <Label htmlFor="scan_timeout">Timeout (seconds)</Label>
                <Input id="scan_timeout" type="number" {...register("scan_timeout")} />
                {errors.scan_timeout && <p className="text-xs text-destructive">{errors.scan_timeout.message}</p>}
                <p className="text-xs text-muted-foreground">Per-host timeout</p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="concurrency">Concurrency</Label>
                <Input id="concurrency" type="number" {...register("concurrency")} />
                {errors.concurrency && <p className="text-xs text-destructive">{errors.concurrency.message}</p>}
                <p className="text-xs text-muted-foreground">Parallel workers</p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="max_hosts">Max Hosts</Label>
                <Input id="max_hosts" type="number" {...register("max_hosts")} />
                {errors.max_hosts && <p className="text-xs text-destructive">{errors.max_hosts.message}</p>}
                <p className="text-xs text-muted-foreground">0 = unlimited</p>
              </div>
            </div>

            <div className="flex items-start gap-2 rounded-lg bg-muted/50 p-3 text-sm">
              <Info className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
              <p className="text-muted-foreground">
                Higher concurrency scans faster but uses more resources. A timeout of 10s and concurrency of 20 is optimal for most audits.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scanner Modules</CardTitle>
            <CardDescription>Enable or disable scan modules by default. Individual scans can override these.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <ToggleRow
              id="port_scan"
              label="Port Scanning"
              description="Scan 14 critical ports (SSH, RDP, SMB, MySQL, etc.) for exposure detection"
            />
            <ToggleRow
              id="web_checks"
              label="Web Security Checks"
              description="HTTP headers, TLS/SSL, WAF detection, cookies, SRI, secrets, security.txt"
            />
            <ToggleRow
              id="dns_checks"
              label="DNS Security Checks"
              description="DNSSEC, zone transfer (AXFR), SPF, DMARC, MX redundancy"
            />
            <ToggleRow
              id="whois_checks"
              label="WHOIS / Domain Expiry"
              description="Check domain registration expiry dates and warn before 30-day threshold"
            />
          </CardContent>
        </Card>

        <div className="flex justify-end">
          <Button type="submit" disabled={loading || !isDirty}>
            {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Save Defaults
          </Button>
        </div>
      </form>
    </div>
  )
}
