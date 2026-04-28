// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { toast } from "sonner"
import { Loader2, UserPlus, MoreHorizontal, Trash2, ArrowLeft } from "lucide-react"
import Link from "next/link"
import { useTranslations } from "next-intl"
import { format as formatDate } from "date-fns"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  useMembers,
  useInviteMember,
  useUpdateMemberRole,
  useRemoveMember,
} from "@/hooks/use-members"
import { useAuthStore } from "@/stores/auth-store"

// Role enum aligned with the backend's Pydantic Literal in
// schemas/organization.py: admin / auditor / viewer.
// Audit B08: previous version had `member` here which the API rejects.
const ROLES = ["admin", "auditor", "viewer"] as const
type Role = (typeof ROLES)[number]

const inviteSchema = z.object({
  email: z.string().email("teamPage.invalidEmail"),
  role: z.enum(ROLES, { message: "teamPage.roleRequired" }),
})

type InviteForm = z.infer<typeof inviteSchema>

const roleColors: Record<string, string> = {
  admin: "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
  auditor: "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
  viewer: "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
}

export default function TeamPage() {
  const t = useTranslations("teamPage")
  const tc = useTranslations("common")
  const currentUser = useAuthStore((s) => s.user)

  const { data: members = [], isLoading } = useMembers()
  const inviteMember = useInviteMember()
  const updateRole = useUpdateMemberRole()
  const removeMember = useRemoveMember()

  const [dialogOpen, setDialogOpen] = useState(false)

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    formState: { errors },
  } = useForm<InviteForm>({
    resolver: zodResolver(inviteSchema),
  })

  const onSubmit = async (data: InviteForm) => {
    try {
      await inviteMember.mutateAsync(data)
      toast.success(t("invitationSent", { email: data.email }))
      reset()
      setDialogOpen(false)
    } catch (err: any) {
      toast.error(t("invitationFailed"), { description: err.message })
    }
  }

  const handleRoleChange = async (memberId: string, newRole: Role) => {
    try {
      await updateRole.mutateAsync({ memberId, role: newRole })
      toast.success(t("roleUpdated", { role: newRole }))
    } catch (err: any) {
      toast.error(t("roleUpdateFailed"), { description: err.message })
    }
  }

  const handleRemove = async (memberId: string, name: string) => {
    try {
      await removeMember.mutateAsync(memberId)
      toast.success(t("memberRemoved", { name }))
    } catch (err: any) {
      toast.error(t("removeFailed"), { description: err.message })
    }
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
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <UserPlus className="mr-2 h-4 w-4" />
              {t("inviteMember")}
            </Button>
          </DialogTrigger>
          <DialogContent>
            <form onSubmit={handleSubmit(onSubmit)}>
              <DialogHeader>
                <DialogTitle>{t("inviteTitle")}</DialogTitle>
                <DialogDescription>{t("inviteDescription")}</DialogDescription>
              </DialogHeader>
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <Label htmlFor="email">{t("emailLabel")}</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder={t("emailPlaceholder")}
                    {...register("email")}
                  />
                  {errors.email && (
                    <p className="text-xs text-destructive">
                      {t(errors.email.message as any)}
                    </p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label>{t("role")}</Label>
                  <Select onValueChange={(v) => setValue("role", v as Role)}>
                    <SelectTrigger>
                      <SelectValue placeholder={t("selectRole")} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin">{t("admin")}</SelectItem>
                      <SelectItem value="auditor">{t("auditor")}</SelectItem>
                      <SelectItem value="viewer">{t("viewer")}</SelectItem>
                    </SelectContent>
                  </Select>
                  {errors.role && (
                    <p className="text-xs text-destructive">
                      {t(errors.role.message as any)}
                    </p>
                  )}
                </div>
              </div>
              <DialogFooter>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setDialogOpen(false)}
                >
                  {tc("cancel")}
                </Button>
                <Button type="submit" disabled={inviteMember.isPending}>
                  {inviteMember.isPending && (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  )}
                  {t("sendInvitation")}
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
          ) : members.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center px-4">
              <h3 className="text-lg font-medium mb-1">{t("noMembers")}</h3>
              <p className="text-sm text-muted-foreground">{t("noMembersDescription")}</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("headerMember")}</TableHead>
                  <TableHead>{t("headerRole")}</TableHead>
                  <TableHead>{t("headerStatus")}</TableHead>
                  <TableHead>{t("headerJoined")}</TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {members.map((member: any) => {
                  // The MemberResponse from the API embeds `user` (UserResponse).
                  // user.full_name can be empty for placeholder users created
                  // by the (legacy) invite flow that didn't yet require a
                  // registration step — fall back to the email then.
                  const fullName = member.user?.full_name?.trim() || member.user?.email || "—"
                  const email = member.user?.email || ""
                  const initials = fullName
                    .split(" ")
                    .map((n: string) => n[0])
                    .filter(Boolean)
                    .join("")
                    .slice(0, 2)
                    .toUpperCase() || "?"
                  // The current user's own row should not offer "remove me" /
                  // "demote me" actions — the API rejects both anyway (admin
                  // self-demotion / removal) but hiding them keeps the UX
                  // tidy and prevents the toast-error confusion.
                  const isSelf = member.user_id === currentUser?.id
                  const status = member.accepted_at ? "active" : "pending"

                  return (
                    <TableRow key={member.id}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <Avatar className="h-8 w-8">
                            <AvatarFallback className="text-xs">{initials}</AvatarFallback>
                          </Avatar>
                          <div>
                            <p className="text-sm font-medium">
                              {fullName}
                              {isSelf && (
                                <span className="ml-2 text-xs text-muted-foreground">
                                  ({t("you")})
                                </span>
                              )}
                            </p>
                            <p className="text-xs text-muted-foreground">{email}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="secondary"
                          className={roleColors[member.role] || ""}
                        >
                          {t(member.role)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={status === "active" ? "secondary" : "outline"}>
                          {t(status)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {member.created_at
                          ? formatDate(new Date(member.created_at), "yyyy-MM-dd")
                          : "—"}
                      </TableCell>
                      <TableCell>
                        {!isSelf && (
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon">
                                <MoreHorizontal className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              {ROLES.filter((r) => r !== member.role).map((r) => (
                                <DropdownMenuItem
                                  key={r}
                                  onClick={() => handleRoleChange(member.id, r)}
                                >
                                  {t(`setAs${r.charAt(0).toUpperCase()}${r.slice(1)}` as any)}
                                </DropdownMenuItem>
                              ))}
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                className="text-destructive"
                                onClick={() => handleRemove(member.id, fullName)}
                              >
                                <Trash2 className="mr-2 h-4 w-4" />
                                {t("removeMember")}
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
