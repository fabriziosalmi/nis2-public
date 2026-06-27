// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { useState } from "react"
import { toast } from "sonner"
import { Bell, Mail, Webhook, Plus, Trash2, TestTube } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { useDocumentTitle } from "@/hooks/use-document-title"

interface Channel {
  id: string
  type: "email" | "webhook" | "slack"
  name: string
  config: Record<string, string>
  events: string[]
  active: boolean
}

// Event option values are stable enum strings; labels are looked up
// at render time under `notificationsPage.events.<value>`.
const eventValues = [
  "scan_completed",
  "scan_failed",
  "critical_finding",
  "score_dropped",
  "domain_expiring",
] as const

export default function NotificationsPage() {
  const t = useTranslations("notificationsPage")
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(t("title"))
  const [channels, setChannels] = useState<Channel[]>([])
  const [showAdd, setShowAdd] = useState(false)
  const [newType, setNewType] = useState<"email" | "webhook">("email")
  const [newName, setNewName] = useState("")
  const [newTarget, setNewTarget] = useState("")
  const [newEvents, setNewEvents] = useState<string[]>(["scan_completed", "critical_finding"])

  const addChannel = () => {
    if (!newName || !newTarget) {
      toast.error(t("nameAndTargetRequired"))
      return
    }
    const channel: Channel = {
      id: Date.now().toString(),
      type: newType,
      name: newName,
      config: newType === "email" ? { email: newTarget } : { url: newTarget },
      events: newEvents,
      active: true,
    }
    setChannels([...channels, channel])
    setNewName("")
    setNewTarget("")
    setShowAdd(false)
    toast.success(t("channelAdded"))
  }

  const removeChannel = (id: string) => {
    setChannels(channels.filter((c) => c.id !== id))
    toast.success(t("channelRemoved"))
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
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Button
                variant={newType === "email" ? "default" : "outline"}
                size="sm"
                onClick={() => setNewType("email")}
              >
                <Mail className="mr-2 h-4 w-4" />
                {t("email")}
              </Button>
              <Button
                variant={newType === "webhook" ? "default" : "outline"}
                size="sm"
                onClick={() => setNewType("webhook")}
              >
                <Webhook className="mr-2 h-4 w-4" />
                {t("webhook")}
              </Button>
            </div>

            <div className="space-y-2">
              <Label>{t("channelName")}</Label>
              <Input
                placeholder={t("channelNamePlaceholder")}
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label>{newType === "email" ? t("emailAddress") : t("webhookUrl")}</Label>
              <Input
                placeholder={newType === "email" ? t("emailPlaceholder") : t("webhookPlaceholder")}
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
              />
            </div>

            <div className="space-y-2">
              <Label>{t("triggerEvents")}</Label>
              <div className="flex flex-wrap gap-2">
                {eventValues.map((ev) => (
                  <Badge
                    key={ev}
                    variant={newEvents.includes(ev) ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() => toggleEvent(ev)}
                  >
                    {t(`events.${ev}` as any)}
                  </Badge>
                ))}
              </div>
            </div>

            <Separator />

            <div className="flex gap-2 justify-end">
              <Button variant="outline" onClick={() => setShowAdd(false)}>{tc("cancel")}</Button>
              <Button onClick={addChannel}>{t("addChannel")}</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {channels.length === 0 && !showAdd ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12 text-center">
            <Bell className="h-12 w-12 text-muted-foreground/50 mb-4" />
            <h3 className="text-lg font-medium">{t("emptyTitle")}</h3>
            <p className="text-sm text-muted-foreground mt-1 mb-4">{t("emptyDescription")}</p>
            <Button onClick={() => setShowAdd(true)}>
              <Plus className="mr-2 h-4 w-4" />
              {t("addFirstChannel")}
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {channels.map((ch) => (
            <Card key={ch.id}>
              <CardContent className="flex items-center gap-4 pt-6">
                <div className="rounded-lg bg-muted p-3">
                  {ch.type === "email" ? <Mail className="h-5 w-5" /> : <Webhook className="h-5 w-5" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{ch.name}</p>
                    <Badge variant="outline" className="capitalize">{ch.type}</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground truncate">
                    {ch.config.email || ch.config.url}
                  </p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {ch.events.map((ev) => (
                      <Badge key={ev} variant="secondary" className="text-xs">
                        {(eventValues as readonly string[]).includes(ev) ? t(`events.${ev}` as any) : ev}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div className="flex gap-1">
                  <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => toast.info(t("testSent"))} aria-label="Send test notification">
                    <TestTube className="h-4 w-4" />
                  </Button>
                  <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive" onClick={() => removeChannel(ch.id)} aria-label="Delete channel">
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
