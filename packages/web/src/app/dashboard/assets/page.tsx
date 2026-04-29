// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { Plus, Trash2, Loader2, Server, Pencil } from "lucide-react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
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
import { useAssets, useCreateAsset, useDeleteAsset, useUpdateAsset } from "@/hooks/use-assets"
import { useDocumentTitle } from "@/hooks/use-document-title"

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
  const t = useTranslations("assets")
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const [dialogOpen, setDialogOpen] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  // editingAsset null = create mode; non-null = edit mode pre-populating
  // the same dialog. We only allow editing `name` and `tags` — type +
  // target_value are immutable to keep historical scan_results referrable.
  const [editingAsset, setEditingAsset] = useState<any | null>(null)
  const { data, isLoading } = useAssets()
  const createAsset = useCreateAsset()
  const updateAsset = useUpdateAsset()
  const deleteAsset = useDeleteAsset()

  const assets = data?.items || []

  const { register, handleSubmit, reset, setValue, formState: { errors } } = useForm<AssetForm>({
    resolver: zodResolver(assetSchema),
  })

  const onSubmit = async (formData: AssetForm) => {
    try {
      if (editingAsset) {
        // Edit path: only name + tags are mutable. Sending target_type /
        // target_value would be a no-op for the backend (PATCH ignores
        // them) but it's clearer to omit.
        await updateAsset.mutateAsync({
          id: editingAsset.id,
          data: {
            name: formData.name,
            tags: formData.tags ? formData.tags.split(",").map((t) => t.trim()) : [],
          },
        })
        toast.success(t("updated"))
      } else {
        await createAsset.mutateAsync({
          name: formData.name,
          target_type: formData.type,
          target_value: formData.target,
          tags: formData.tags ? formData.tags.split(",").map((t) => t.trim()) : [],
        } as any)
        toast.success(t("added"))
      }
      reset()
      setEditingAsset(null)
      setDialogOpen(false)
    } catch (err: any) {
      toast.error(editingAsset ? t("updateFailed") : t("addFailed"), { description: err.message })
    }
  }

  const startEdit = (asset: any) => {
    setEditingAsset(asset)
    reset({
      name: asset.name,
      type: asset.target_type,
      target: asset.target_value,
      tags: (asset.tags || []).join(", "),
    })
    setDialogOpen(true)
  }

  const handleDelete = async (id: string) => {
    try {
      await deleteAsset.mutateAsync(id)
      toast.success(t("removed"))
      setDeleteId(null)
    } catch (err: any) {
      toast.error(t("deleteFailed"), { description: err.message })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Dialog
          open={dialogOpen}
          onOpenChange={(open) => {
            setDialogOpen(open)
            // Closing the dialog should also drop edit state so the next
            // "+ Add Asset" click is in clean create mode again.
            if (!open) {
              setEditingAsset(null)
              reset({ name: "", type: "", target: "", tags: "" })
            }
          }}
        >
          <DialogTrigger asChild>
            <Button onClick={() => { setEditingAsset(null); reset({ name: "", type: "", target: "", tags: "" }) }}>
              <Plus className="mr-2 h-4 w-4" />{t("addAsset")}
            </Button>
          </DialogTrigger>
          <DialogContent>
            <form onSubmit={handleSubmit(onSubmit)}>
              <DialogHeader>
                <DialogTitle>{editingAsset ? t("editAsset") : t("addNewAsset")}</DialogTitle>
                <DialogDescription>
                  {editingAsset ? t("editDescription") : t("dialogDescription")}
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="name">{t("name")}</Label>
                  <Input id="name" placeholder={t("namePlaceholder")} {...register("name")} />
                  {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
                </div>
                <div className="space-y-2">
                  <Label>{t("type")}</Label>
                  <Select
                    value={editingAsset?.target_type}
                    onValueChange={(v) => setValue("type", v)}
                    disabled={!!editingAsset}
                  >
                    <SelectTrigger><SelectValue placeholder={t("selectType")} /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="domain">{t("domain")}</SelectItem>
                      <SelectItem value="ip">{t("ip")}</SelectItem>
                      <SelectItem value="cidr">{t("cidr")}</SelectItem>
                    </SelectContent>
                  </Select>
                  {errors.type && <p className="text-xs text-destructive">{errors.type.message}</p>}
                  {editingAsset && (
                    <p className="text-xs text-muted-foreground">{t("typeImmutable")}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="target">{t("target")}</Label>
                  <Input
                    id="target"
                    placeholder={t("targetPlaceholder")}
                    {...register("target")}
                    disabled={!!editingAsset}
                  />
                  {errors.target && <p className="text-xs text-destructive">{errors.target.message}</p>}
                  {editingAsset && (
                    <p className="text-xs text-muted-foreground">{t("targetImmutable")}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="tags">{t("tagsLabel")}</Label>
                  <Input id="tags" placeholder={t("tagsPlaceholder")} {...register("tags")} />
                </div>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setDialogOpen(false)}>{tc("cancel")}</Button>
                <Button type="submit" disabled={createAsset.isPending || updateAsset.isPending}>
                  {(createAsset.isPending || updateAsset.isPending) && (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  )}
                  {editingAsset ? t("save") : t("addAsset")}
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
              <h3 className="text-lg font-medium mb-1">{t("emptyTitle")}</h3>
              <p className="text-sm text-muted-foreground mb-6 max-w-sm">{t("emptyDescription")}</p>
              <Button onClick={() => setDialogOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                {t("addFirstAsset")}
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("name")}</TableHead>
                  <TableHead>{t("type")}</TableHead>
                  <TableHead>{t("target")}</TableHead>
                  <TableHead>{t("tags")}</TableHead>
                  <TableHead>{t("status")}</TableHead>
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
                        {asset.is_active ? t("active") : t("inactive")}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {deleteId === asset.id ? (
                        <div className="flex items-center gap-1">
                          <Button variant="destructive" size="sm" onClick={() => handleDelete(asset.id)} disabled={deleteAsset.isPending}>{t("yes")}</Button>
                          <Button variant="ghost" size="sm" onClick={() => setDeleteId(null)}>{t("no")}</Button>
                        </div>
                      ) : (
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => startEdit(asset)}
                            aria-label={t("editAsset")}
                          >
                            <Pencil className="h-4 w-4 text-muted-foreground" />
                          </Button>
                          <Button variant="ghost" size="icon" onClick={() => setDeleteId(asset.id)} aria-label={tc("delete")}>
                            <Trash2 className="h-4 w-4 text-muted-foreground" />
                          </Button>
                        </div>
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
