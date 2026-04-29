// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import Link from "next/link"
import { Building2, UserCog, Radar, Users, Key, Bell, ScrollText, ChevronRight } from "lucide-react"
import { useTranslations } from "next-intl"
import { Card, CardContent } from "@/components/ui/card"
import { useDocumentTitle } from "@/hooks/use-document-title"

const settingsLinks = [
  {
    title: "Organization",
    description: "Company name, slug, and general organization settings",
    href: "/dashboard/settings/organization",
    icon: Building2,
  },
  {
    title: "Profile",
    description: "Your name, email, locale, and password",
    href: "/dashboard/settings/profile",
    icon: UserCog,
  },
  {
    title: "Scan Defaults",
    description: "Default scan timeout, concurrency, features, and limits",
    href: "/dashboard/settings/scan-defaults",
    icon: Radar,
  },
  {
    title: "Team Management",
    description: "Manage team members, roles, and permissions",
    href: "/dashboard/settings/team",
    icon: Users,
  },
  {
    title: "API Keys",
    description: "Create and manage API keys for CI/CD integration",
    href: "/dashboard/settings/api-keys",
    icon: Key,
  },
  {
    title: "Notifications",
    description: "Configure email and webhook notification channels",
    href: "/dashboard/settings/notifications",
    icon: Bell,
  },
  {
    title: "Audit Log",
    description: "View a log of all actions taken in your organization",
    href: "/dashboard/settings/audit-log",
    icon: ScrollText,
  },
]

export default function SettingsPage() {
  const tc = useTranslations("common")
  // v2.4.24 audit a11y-11: per-page <title>.
  useDocumentTitle(tc("settings"))
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">{tc("settings")}</h1>
        <p className="text-muted-foreground">Manage your organization and account settings</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {settingsLinks.map((link) => (
          <Link key={link.href} href={link.href}>
            <Card className="transition-colors hover:bg-muted/50 cursor-pointer h-full">
              <CardContent className="flex items-center gap-4 pt-6">
                <div className="rounded-lg bg-muted p-3">
                  <link.icon className="h-5 w-5" />
                </div>
                <div className="flex-1">
                  <h3 className="font-semibold">{link.title}</h3>
                  <p className="text-sm text-muted-foreground">{link.description}</p>
                </div>
                <ChevronRight className="h-4 w-4 text-muted-foreground" />
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
