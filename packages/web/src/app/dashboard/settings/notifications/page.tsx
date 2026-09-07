// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// Notification channels — the delivery targets for Art. 23 deadline alerts.
//
// This screen used to be a placeholder: channels lived in `useState`, were lost
// on navigation, and `addChannel` raised a success toast for an operation that
// never left the browser. There was no endpoint behind it either. Meanwhile the
// Celery beat task that dispatches the 24h / 72h / 1-month alerts reads
// NotificationChannel rows, so it always found none and fell back to emailing
// organisation admins — which needs SMTP configured. On a deployment with
// neither, the alert for a legally binding deadline went to the application log.
//
// Everything here now goes through /api/v1/notification-channels.

"use client"

import { useState } from "react"
import { toast } from "sonner"
import { Bell, Mail, Webhook, Plus, Trash2, TestTube, Loader2, MessageSquare } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { useDocumentTitle } from "@/hooks/use-document-title"
import {
  useNotificationChannels,
  useCreateNotificationChannel,
  useDeleteNotificationChannel,
  useTestNotificationChannel,
} from "@/hooks/use-notification-channels"

type ChannelType = "email" | "webhook" | "slack"

// Event option values are stable enum strings; labels are looked up
// at render time under `notificationsPage.events.<value>`.
const eventValues = [
  "incident_deadline",
  "scan_completed",
  "scan_failed",
  "critical_finding",
  "score_dropped",
  "domain_expiring",
] as const

const TYPE_ICON: Record<ChannelType, typeof Mail> = {
  email: Mail,
  webhook: Webhook,
  // lucide-react 1.x dropped the brand icons; MessageSquare is the neutral
  // stand-in for a chat destination.
  slack: MessageSquare,
}

/** The API stores each type's destination under a different config key, and the
 *  dispatcher reads exactly these names. Keeping the mapping in one place stops
 *  the form and the backend drifting. */
const TARGET_KEY: Record<ChannelType, string> = {
  email: "email",
  webhook: "url",
  slack: "webhook_url",
}

export default function NotificationsPage() {
  const t = useTranslations("notificationsPage")
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))

  const { data: channels, isLoading } = useNotificationChannels()
  const createChannel = useCreateNotificationChannel()
  const deleteChannel = useDeleteNotificationChannel()
  const testChannel = useTestNotificationChannel()

  const [showAdd, setShowAdd] = useState(false)
  const [newType, setNewType] = useState<ChannelType>("email")
  const [newName, setNewName] = useState("")
  const [newTarget, setNewTarget] = useState("")
  const [newSecret, setNewSecret] = useState("")
  const [newEvents, setNewEvents] = useState<string[]>(["incident_deadline", "critical_finding"])

  const addChannel = async () => {
    if (!newName || !newTarget) {
      toast.error(t("nameAndTargetRequired"))
      return
    }
    const config: Record<string, string> = { [TARGET_KEY[newType]]: newTarget }
    if (newType === "webhook" && newSecret) config.secret = newSecret
    try {
      await createChannel.mutateAsync({
        channel_type: newType,
        name: newName,
        config,
        events: newEvents,
      })
      setNewName("")
      setNewTarget("")
      setNewSecret("")
      setShowAdd(false)
      toast.success(t("channelAdded"))
    } catch (err: any) {
      toast.error(t("channelAddFailed"), { description: err.message })
    }
  }

  const removeChannel = async (id: string) => {
    try {
      await deleteChannel.mutateAsync(id)
      toast.success(t("channelRemoved"))
    } catch (err: any) {
      toast.error(t("channelRemoveFailed"), { description: err.message })
    }
  }

  const sendTest = async (id: string) => {
    try {
      await testChannel.mutateAsync(id)
      toast.success(t("testSent"))
    } catch (err: any) {
      toast.error(t("testFailed"), { description: err.message })
    }
  }

  const toggleEvent = (event: string) => {
    setNewEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">{t("subtitle")}</p>
        </div>
        <Button onClick={() => setShowAdd(!showAdd)}>
          <Plus className="mr-2 h-4 w-4" />
          {t("addChannel")}
        </Button>
      </div>

      {showAdd && (
        <Card>
          <CardHeader>
            <CardTitle>{t("newChannelTitle")}</CardTitle>
            <CardDescription>{t("newChannelDescription")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              {(["email", "webhook", "slack"] as const).map((type) => {
                const Icon = TYPE_ICON[type]
                return (
                  <Button
                    key={type}
                    type="button"
                    variant={newType === type ? "default" : "outline"}
                    onClick={() => { setNewType(type); setNewTarget("") }}
                  >
                    <Icon className="mr-2 h-4 w-4" />
                    {t(`channelType.${type}`)}
                  </Button>
                )
              })}
            </div>

            <div className="space-y-2">
              <Label htmlFor="ch-name">{t("channelName")}</Label>
              <Input
                id="ch-name"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder={t("channelNamePlaceholder")}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="ch-target">{t(`targetLabel.${newType}`)}</Label>
              <Input
                id="ch-target"
                type={newType === "email" ? "email" : "url"}
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
                placeholder={t(`targetPlaceholder.${newType}`)}
              />
              {newType !== "email" && (
                <p className="text-xs text-muted-foreground">{t("ssrfHint")}</p>
              )}
            </div>

            {newType === "webhook" && (
              <div className="space-y-2">
                <Label htmlFor="ch-secret">{t("webhookSecret")}</Label>
                <Input
                  id="ch-secret"
                  type="password"
                  value={newSecret}
                  onChange={(e) => setNewSecret(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">{t("webhookSecretHint")}</p>
              </div>
            )}

            <div className="space-y-2">
              <Label>{t("triggerEvents")}</Label>
              <div className="flex flex-wrap gap-2">
                {eventValues.map((event) => (
                  <Button
                    key={event}
                    type="button"
                    size="sm"
                    variant={newEvents.includes(event) ? "default" : "outline"}
                    onClick={() => toggleEvent(event)}
                  >
                    {t(`events.${event}`)}
                  </Button>
                ))}
              </div>
            </div>

            <Separator />

            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setShowAdd(false)}>{tc("cancel")}</Button>
              <Button onClick={addChannel} disabled={createChannel.isPending}>
                {createChannel.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {tc("save")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            {t("configuredChannels")}
          </CardTitle>
          <CardDescription>{t("art23Hint")}</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
            </div>
          ) : !channels?.length ? (
            <p className="py-8 text-center text-sm text-muted-foreground">{t("emptyDescription")}</p>
          ) : (
            <ul className="divide-y">
              {channels.map((ch: any) => {
                const Icon = TYPE_ICON[ch.channel_type as ChannelType] ?? Bell
                const target = ch.config?.[TARGET_KEY[ch.channel_type as ChannelType]] ?? ""
                return (
                  <li key={ch.id} className="flex items-center justify-between gap-4 py-3">
                    <div className="flex min-w-0 items-center gap-3">
                      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium">{ch.name}</p>
                        <p className="truncate text-xs text-muted-foreground">{target}</p>
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      {!ch.is_active && <Badge variant="outline">{t("inactive")}</Badge>}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => sendTest(ch.id)}
                        disabled={testChannel.isPending}
                        aria-label={t("sendTest")}
                        title={t("sendTest")}
                      >
                        <TestTube className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeChannel(ch.id)}
                        disabled={deleteChannel.isPending}
                        aria-label={tc("delete")}
                        title={tc("delete")}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </li>
                )
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
