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
      toast.success("API key created")
      reset()
    } catch (err: any) {
      toast.error("Failed to create API key", { description: err.message })
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey)
      toast.success("API key copied to clipboard")
    }
  }

  const handleRevoke = (id: string) => {
    toast.success("API key revoked")
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
          <h1 className="text-3xl font-bold tracking-tight">API Keys</h1>
          <p className="text-muted-foreground">Manage API keys for programmatic access</p>
        </div>
        <Dialog open={createOpen} onOpenChange={(open) => { if (!open) handleCloseCreate(); else setCreateOpen(true); }}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create API Key
            </Button>
          </DialogTrigger>
          <DialogContent>
            {newKey ? (
              <>
                <DialogHeader>
                  <DialogTitle>API Key Created</DialogTitle>
                  <DialogDescription>
                    Copy this key now. You will not be able to see it again.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="flex items-center gap-2 rounded-lg bg-muted p-3">
                    <Key className="h-4 w-4 text-muted-foreground shrink-0" />
                    <code className="flex-1 text-sm font-mono break-all">{newKey}</code>
                    <Button variant="ghost" size="icon" onClick={handleCopy}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                  <p className="text-sm text-destructive font-medium">
                    Store this key securely. It will only be shown once.
                  </p>
                </div>
                <DialogFooter>
                  <Button onClick={handleCloseCreate}>Done</Button>
                </DialogFooter>
              </>
            ) : (
              <form onSubmit={handleSubmit(onSubmit)}>
                <DialogHeader>
                  <DialogTitle>Create New API Key</DialogTitle>
                  <DialogDescription>Give your API key a descriptive name</DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">Key Name</Label>
                    <Input id="name" placeholder="e.g., CI/CD Pipeline" {...register("name")} />
                    {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
                  </div>
                </div>
                <DialogFooter>
                  <Button type="button" variant="outline" onClick={handleCloseCreate}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={loading}>
                    {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    Create Key
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
                <TableHead>Name</TableHead>
                <TableHead>Key Prefix</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead>Status</TableHead>
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
                      {key.status}
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
                              Confirm
                            </Button>
                            <Button variant="ghost" size="sm" onClick={() => setRevokeId(null)}>
                              Cancel
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
          <CardTitle className="text-sm">API Documentation</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Use your API key in the <code className="rounded bg-muted px-1 py-0.5 text-xs">Authorization</code> header
            as a Bearer token. See the{" "}
            <a href="#" className="font-medium text-primary hover:underline">
              API documentation
            </a>{" "}
            for available endpoints and usage examples.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
