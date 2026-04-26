// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { Plus, Trash2, Loader2, Server } from "lucide-react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useAssets, useCreateAsset, useDeleteAsset } from "@/hooks/use-assets"

const assetSchema = z.object({
  name: z.string().min(1, "Name is required"),
  type: z.string().min(1, "Type is required"),
  target: z.string().min(1, "Target value is required"),
  tags: z.string().optional(),
})

type AssetForm = z.infer<typeof assetSchema>

const typeColors: Record<string, string> = {
  domain: "bg-blue-100 text-blue-800",
  ip: "bg-green-100 text-green-800",
  cidr: "bg-orange-100 text-orange-800",
}

export default function AssetsPage() {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const { data, isLoading } = useAssets()
  const createAsset = useCreateAsset()
  const deleteAsset = useDeleteAsset()

  const assets = data?.items || []

  const { register, handleSubmit, reset, setValue, formState: { errors } } = useForm<AssetForm>({
    resolver: zodResolver(assetSchema),
  })

  const onSubmit = async (formData: AssetForm) => {
    try {
      await createAsset.mutateAsync({
        name: formData.name,
        target_type: formData.type,
        target_value: formData.target,
        tags: formData.tags ? formData.tags.split(",").map((t) => t.trim()) : [],
      } as any)
      toast.success("Asset added")
      reset()
      setDialogOpen(false)
    } catch (err: any) {
      toast.error("Failed to add asset", { description: err.message })
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await deleteAsset.mutateAsync(id)
      toast.success("Asset removed")
      setDeleteId(null)
    } catch (err: any) {
      toast.error("Failed to delete", { description: err.message })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Assets</h1>
          <p className="text-muted-foreground">Manage your monitored assets and targets</p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button><Plus className="mr-2 h-4 w-4" />Add Asset</Button>
          </DialogTrigger>
          <DialogContent>
            <form onSubmit={handleSubmit(onSubmit)}>
              <DialogHeader>
                <DialogTitle>Add New Asset</DialogTitle>
                <DialogDescription>Add a domain, IP, or CIDR block to scan for NIS2 compliance</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="name">Name</Label>
                  <Input id="name" placeholder="e.g. Production Web Server" {...register("name")} />
                  {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select onValueChange={(v) => setValue("type", v)}>
                    <SelectTrigger><SelectValue placeholder="Select type" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="domain">Domain</SelectItem>
                      <SelectItem value="ip">IP Address</SelectItem>
                      <SelectItem value="cidr">CIDR Block</SelectItem>
                    </SelectContent>
                  </Select>
                  {errors.type && <p className="text-xs text-destructive">{errors.type.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="target">Target</Label>
                  <Input id="target" placeholder="e.g. example.com or 10.0.0.0/24" {...register("target")} />
                  {errors.target && <p className="text-xs text-destructive">{errors.target.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tags">Tags (comma-separated)</Label>
                  <Input id="tags" placeholder="e.g. production, web, critical" {...register("tags")} />
                </div>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>Cancel</Button>
                <Button type="submit" disabled={createAsset.isPending}>
                  {createAsset.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Add Asset
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : assets.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center px-4">
              <div className="rounded-full bg-muted p-4 mb-4">
                <Server className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-medium mb-1">No assets configured</h3>
              <p className="text-sm text-muted-foreground mb-6 max-w-sm">
                Add domains, IPs, or CIDR ranges to monitor. Assets are the targets you scan for NIS2 compliance.
              </p>
              <Button onClick={() => setDialogOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Add Your First Asset
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assets.map((asset: any) => (
                  <TableRow key={asset.id}>
                    <TableCell className="font-medium">{asset.name}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className={typeColors[asset.target_type] || ""}>
                        {asset.target_type}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">{asset.target_value}</TableCell>
                    <TableCell>
                      <div className="flex gap-1 flex-wrap">
                        {(asset.tags || []).map((tag: string) => (
                          <Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={asset.is_active ? "secondary" : "outline"}>
                        {asset.is_active ? "active" : "inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {deleteId === asset.id ? (
                        <div className="flex items-center gap-1">
                          <Button variant="destructive" size="sm" onClick={() => handleDelete(asset.id)} disabled={deleteAsset.isPending}>Yes</Button>
                          <Button variant="ghost" size="sm" onClick={() => setDeleteId(null)}>No</Button>
                        </div>
                      ) : (
                        <Button variant="ghost" size="icon" onClick={() => setDeleteId(asset.id)}>
                          <Trash2 className="h-4 w-4 text-muted-foreground" />
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
