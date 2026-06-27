// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
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
import { useFormatDate } from "@/lib/dates"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
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
} from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useApiKeys, useCreateApiKey, useRevokeApiKey } from "@/hooks/use-api-keys"
import { useDocumentTitle } from "@/hooks/use-document-title"

const createKeySchema = z.object({
  name: z.string().min(1, "apiKeysPage.nameRequired").max(256),
})

type CreateKeyForm = z.infer<typeof createKeySchema>

export default function ApiKeysPage() {
  const t = useTranslations("apiKeysPage")
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const formatDate = useFormatDate()
  const { data: keysData, isLoading } = useApiKeys()
  const createKey = useCreateApiKey()
  const revokeKey = useRevokeApiKey()

  const [createOpen, setCreateOpen] = useState(false)
  // The plaintext key returned by the API on creation. Held in
  // component state and shown ONCE — server-side we only store the
  // sha256 hash, so once the dialog closes the user cannot retrieve
  // it again. Cleared on close.
  const [newKey, setNewKey] = useState<string | null>(null)
  const [revokeId, setRevokeId] = useState<string | null>(null)

  const keys = keysData?.items || []

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CreateKeyForm>({
    resolver: zodResolver(createKeySchema),
  })

  const onSubmit = async (data: CreateKeyForm) => {
    try {
      const created = await createKey.mutateAsync(data)
      // The API returns ApiKeyCreated which extends ApiKeyResponse with
      // raw_key — this is the plaintext shown once.
      setNewKey(created.raw_key)
      toast.success(t("keyCreated"))
      reset()
    } catch (err: any) {
      toast.error(t("keyCreateFailed"), { description: err.message })
    }
  }

  const handleCopy = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey)
      toast.success(t("keyCopied"))
    }
  }

  const handleRevoke = async (id: string) => {
    try {
      await revokeKey.mutateAsync(id)
      toast.success(t("keyRevoked"))
      setRevokeId(null)
    } catch (err: any) {
      toast.error(t("keyRevokeFailed"), { description: err.message })
    }
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
          <Link href="/dashboard/settings" aria-label="Back to settings">
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <div className="flex-1">
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Dialog
          open={createOpen}
          onOpenChange={(open) => {
            if (!open) handleCloseCreate()
            else setCreateOpen(true)
          }}
        >
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
                    <Button variant="ghost" size="icon" onClick={handleCopy} aria-label="Copy key to clipboard">
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
                    {errors.name && (
                      <p className="text-xs text-destructive">{t(errors.name.message as any)}</p>
                    )}
                  </div>
                </div>
                <DialogFooter>
                  <Button type="button" variant="outline" onClick={handleCloseCreate}>
                    {tc("cancel")}
                  </Button>
                  <Button type="submit" disabled={createKey.isPending}>
                    {createKey.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
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
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : keys.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center px-4">
              <div className="rounded-full bg-muted p-4 mb-4">
                <Key className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-medium mb-1">{t("noKeys")}</h3>
              <p className="text-sm text-muted-foreground max-w-sm">{t("noKeysDescription")}</p>
            </div>
          ) : (
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
                {keys.map((key: any) => (
                  <TableRow key={key.id}>
                    <TableCell className="font-medium">{key.name}</TableCell>
                    <TableCell>
                      <code className="rounded bg-muted px-2 py-1 text-xs font-mono">
                        {key.key_prefix}…
                      </code>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatDate(key.created_at, "PP")}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {key.last_used_at ? formatDate(key.last_used_at, "Pp") : t("neverUsed")}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={key.is_active ? "secondary" : "outline"}
                        className={!key.is_active ? "text-red-600" : ""}
                      >
                        {key.is_active ? t("active") : t("revoked")}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {key.is_active && (
                        revokeId === key.id ? (
                          <div className="flex items-center gap-1">
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => handleRevoke(key.id)}
                              disabled={revokeKey.isPending}
                            >
                              {t("confirm")}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setRevokeId(null)}
                            >
                              {tc("cancel")}
                            </Button>
                          </div>
                        ) : (
                          <Button variant="ghost" size="icon" onClick={() => setRevokeId(key.id)} aria-label="Delete API key">
                            <Trash2 className="h-4 w-4 text-muted-foreground" />
                          </Button>
                        )
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
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
