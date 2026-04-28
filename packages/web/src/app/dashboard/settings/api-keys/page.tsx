// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Plus, Loader2, Copy, ArrowLeft, Key, Trash2 } from "lucide-react"
import Link from "next/link"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogClose,
} from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

const createKeySchema = z.object({
  name: z.string().min(1, "Name is required"),
})

type CreateKeyForm = z.infer<typeof createKeySchema>

const sampleKeys = [
  { id: "1", name: "CI/CD Pipeline", prefix: "nis2_pk_live_abc1", created: "2026-01-15", last_used: "2026-03-27", status: "active" },
  { id: "2", name: "Monitoring Integration", prefix: "nis2_pk_live_def2", created: "2026-02-20", last_used: "2026-03-26", status: "active" },
  { id: "3", name: "Development Testing", prefix: "nis2_pk_test_ghi3", created: "2025-11-10", last_used: "2026-03-20", status: "active" },
  { id: "4", name: "Legacy Integration", prefix: "nis2_pk_live_jkl4", created: "2025-06-01", last_used: "2025-12-15", status: "revoked" },
]

export default function ApiKeysPage() {
  const t = useTranslations("apiKeysPage")
  const tc = useTranslations("common")
  const [createOpen, setCreateOpen] = useState(false)
  const [newKey, setNewKey] = useState<string | null>(null)
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CreateKeyForm>({
    resolver: zodResolver(createKeySchema),
  })

  const onSubmit = async (data: CreateKeyForm) => {
    setLoading(true)
    try {
      // api.createApiKey would be called here
      const generatedKey = `nis2_pk_live_${Math.random().toString(36).substring(2, 34)}`
      setNewKey(generatedKey)
      toast.success(t("keyCreated"))
      reset()
    } catch (err: any) {
      toast.error(t("keyCreateFailed"), { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey)
      toast.success(t("keyCopied"))
    }
  }

  const handleRevoke = (id: string) => {
    toast.success(t("keyRevoked"))
    setRevokeId(null)
  }

  const handleCloseCreate = () => {
    setCreateOpen(false)
    setNewKey(null)
    reset()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link href="/dashboard/settings">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div className="flex-1">
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Dialog open={createOpen} onOpenChange={(open) => { if (!open) handleCloseCreate(); else setCreateOpen(true); }}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              {t("create")}
            </Button>
          </DialogTrigger>
          <DialogContent>
            {newKey ? (
              <>
                <DialogHeader>
                  <DialogTitle>{t("createdTitle")}</DialogTitle>
                  <DialogDescription>{t("createdDescription")}</DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="flex items-center gap-2 rounded-lg bg-muted p-3">
                    <Key className="h-4 w-4 text-muted-foreground shrink-0" />
                    <code className="flex-1 text-sm font-mono break-all">{newKey}</code>
                    <Button variant="ghost" size="icon" onClick={handleCopy}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                  <p className="text-sm text-destructive font-medium">{t("storeSecurely")}</p>
                </div>
                <DialogFooter>
                  <Button onClick={handleCloseCreate}>{t("done")}</Button>
                </DialogFooter>
              </>
            ) : (
              <form onSubmit={handleSubmit(onSubmit)}>
                <DialogHeader>
                  <DialogTitle>{t("createNewTitle")}</DialogTitle>
                  <DialogDescription>{t("createNewDescription")}</DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">{t("keyName")}</Label>
                    <Input id="name" placeholder={t("keyNamePlaceholder")} {...register("name")} />
                    {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
                  </div>
                </div>
                <DialogFooter>
                  <Button type="button" variant="outline" onClick={handleCloseCreate}>
                    {tc("cancel")}
                  </Button>
                  <Button type="submit" disabled={loading}>
                    {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    {t("createKey")}
                  </Button>
                </DialogFooter>
              </form>
            )}
          </DialogContent>
        </Dialog>
      </div>

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("name")}</TableHead>
                <TableHead>{t("keyPrefix")}</TableHead>
                <TableHead>{t("created")}</TableHead>
                <TableHead>{t("lastUsed")}</TableHead>
                <TableHead>{t("status")}</TableHead>
                <TableHead className="w-12"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sampleKeys.map((key) => (
                <TableRow key={key.id}>
                  <TableCell className="font-medium">{key.name}</TableCell>
                  <TableCell>
                    <code className="rounded bg-muted px-2 py-1 text-xs font-mono">{key.prefix}...</code>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{key.created}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{key.last_used}</TableCell>
                  <TableCell>
                    <Badge variant={key.status === "active" ? "secondary" : "outline"} className={key.status === "revoked" ? "text-red-600" : ""}>
                      {key.status === "active" ? t("active") : key.status === "revoked" ? t("revoked") : key.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {key.status === "active" && (
                      <>
                        {revokeId === key.id ? (
                          <div className="flex items-center gap-1">
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => handleRevoke(key.id)}
                            >
                              {t("confirm")}
                            </Button>
                            <Button variant="ghost" size="sm" onClick={() => setRevokeId(null)}>
                              {tc("cancel")}
                            </Button>
                          </div>
                        ) : (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setRevokeId(key.id)}
                          >
                            <Trash2 className="h-4 w-4 text-muted-foreground" />
                          </Button>
                        )}
                      </>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">{t("documentation")}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{t("documentationDescription")}</p>
        </CardContent>
      </Card>
    </div>
  )
}
