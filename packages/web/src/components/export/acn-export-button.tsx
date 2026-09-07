// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// ACN export — the Italian differentiator, previously reachable only by
// reading the OpenAPI schema.
//
// GET /acn-export/art18 and /acn-export/bia shape the vendor inventory and the
// business-impact analysis for the ACN portal. They are the single feature that
// distinguishes this platform from a generic scanner in the market it is aimed
// at, and no screen linked to either.
//
// The schema is labelled preliminary in the payload the API returns: the
// official ACN modello di categorizzazione is expected from the Tavolo NIS, and
// this shape will need re-validation against it. The button says so, because a
// customer who submits an export believing it is the official format and finds
// out otherwise at the portal is a worse outcome than one who was told.

"use client"

import { useState } from "react"
import { toast } from "sonner"
import { useTranslations } from "next-intl"
import { Download, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { errorMessage } from "@/lib/utils"

interface Props {
  kind: "art18" | "bia"
  fetcher: () => Promise<unknown>
}

export function AcnExportButton({ kind, fetcher }: Props) {
  const t = useTranslations("acnExport")
  const [loading, setLoading] = useState(false)

  const run = async () => {
    setLoading(true)
    try {
      const payload = await fetcher()
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `acn-${kind}-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      toast.success(t("done"), { description: t("preliminaryNotice") })
    } catch (err: unknown) {
      toast.error(t("failed"), { description: errorMessage(err) })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Button variant="outline" onClick={run} disabled={loading} title={t("preliminaryNotice")}>
      {loading ? (
        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
      ) : (
        <Download className="mr-2 h-4 w-4" />
      )}
      {t(kind === "art18" ? "art18" : "bia")}
    </Button>
  )
}
