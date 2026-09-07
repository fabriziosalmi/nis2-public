// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// A field-spec driven create/edit dialog.
//
// Vendors (Art. 18), BIA processes and incidents (Art. 23) all needed the same
// thing at the same time: a form that did not exist, over a REST API that was
// already complete. Their field sets differ too much to share a component
// outright and are too similar to justify three near-identical 200-line forms,
// so each page declares its fields and this renders them.
//
// Deliberately not react-hook-form + zod, which the auth pages use: those
// validate a fixed schema known at build time, whereas the shape here is data.
// Required-field checking is done inline; everything else is the API's job, and
// its 422 detail is surfaced to the caller rather than duplicated client-side.

"use client"

import { useEffect, useState } from "react"
import { useTranslations } from "next-intl"
import { Loader2 } from "lucide-react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"

export type FieldSpec = {
  name: string
  label: string
  type: "text" | "email" | "number" | "textarea" | "date" | "select" | "checkbox"
  required?: boolean
  placeholder?: string
  hint?: string
  options?: { value: string; label: string }[]
  min?: number
  max?: number
  /** Render this field on its own row rather than sharing the two-column grid. */
  full?: boolean
}

export type EntityValues = Record<string, unknown>

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  fields: FieldSpec[]
  initialValues?: EntityValues
  submitting?: boolean
  onSubmit: (values: EntityValues) => void | Promise<void>
}

function emptyFor(field: FieldSpec): unknown {
  if (field.type === "checkbox") return false
  if (field.type === "number") return ""
  return ""
}

export function EntityFormDialog({
  open,
  onOpenChange,
  title,
  description,
  fields,
  initialValues,
  submitting,
  onSubmit,
}: Props) {
  const tc = useTranslations("common")
  const [values, setValues] = useState<EntityValues>({})
  const [missing, setMissing] = useState<string[]>([])

  // Reset on every open so an edit dialog never shows the previous entity's
  // values, and a create dialog never shows the last thing that was edited.
  useEffect(() => {
    if (!open) return
    const seeded: EntityValues = {}
    for (const f of fields) {
      const provided = initialValues?.[f.name]
      seeded[f.name] = provided === undefined || provided === null ? emptyFor(f) : provided
    }
    setValues(seeded)
    setMissing([])
    // `fields` and `initialValues` are stable per open in practice; keying the
    // reset on `open` alone avoids clobbering what the user is typing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const set = (name: string, value: unknown) =>
    setValues((prev) => ({ ...prev, [name]: value }))

  const submit = async () => {
    const blank = fields
      .filter((f) => f.required)
      .filter((f) => {
        const v = values[f.name]
        return v === "" || v === undefined || v === null
      })
      .map((f) => f.name)
    if (blank.length) {
      setMissing(blank)
      return
    }

    // Strip empties so PATCH sends only what the user actually filled, and
    // coerce numeric fields — an <input type="number"> yields a string, and the
    // API rejects "3" where it wants 3.
    const payload: EntityValues = {}
    for (const f of fields) {
      const v = values[f.name]
      if (v === "" || v === undefined || v === null) continue
      payload[f.name] = f.type === "number" ? Number(v) : v
    }
    await onSubmit(payload)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>

        <div className="grid gap-4 py-2 sm:grid-cols-2">
          {fields.map((f) => {
            const invalid = missing.includes(f.name)
            const id = `field-${f.name}`
            return (
              <div
                key={f.name}
                className={`space-y-2 ${f.full || f.type === "textarea" ? "sm:col-span-2" : ""}`}
              >
                {f.type !== "checkbox" && (
                  <Label htmlFor={id}>
                    {f.label}
                    {f.required && <span aria-hidden className="ml-1 text-destructive">*</span>}
                  </Label>
                )}

                {f.type === "textarea" ? (
                  <textarea
                    id={id}
                    rows={3}
                    className="flex w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"
                    value={String(values[f.name] ?? "")}
                    placeholder={f.placeholder}
                    aria-invalid={invalid}
                    aria-describedby={f.hint ? `${id}-hint` : undefined}
                    onChange={(e) => set(f.name, e.target.value)}
                  />
                ) : f.type === "select" ? (
                  <Select
                    value={String(values[f.name] ?? "")}
                    onValueChange={(v) => set(f.name, v)}
                  >
                    <SelectTrigger id={id} aria-invalid={invalid}>
                      <SelectValue placeholder={f.placeholder} />
                    </SelectTrigger>
                    <SelectContent>
                      {f.options?.map((o) => (
                        <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : f.type === "checkbox" ? (
                  <label htmlFor={id} className="flex items-center gap-2 pt-6 text-sm">
                    <input
                      id={id}
                      type="checkbox"
                      className="h-4 w-4 rounded border-input"
                      checked={!!values[f.name]}
                      onChange={(e) => set(f.name, e.target.checked)}
                    />
                    {f.label}
                  </label>
                ) : (
                  <Input
                    id={id}
                    type={f.type}
                    min={f.min}
                    max={f.max}
                    value={String(values[f.name] ?? "")}
                    placeholder={f.placeholder}
                    aria-invalid={invalid}
                    aria-describedby={f.hint ? `${id}-hint` : undefined}
                    onChange={(e) => set(f.name, e.target.value)}
                  />
                )}

                {f.hint && (
                  <p id={`${id}-hint`} className="text-xs text-muted-foreground">{f.hint}</p>
                )}
                {invalid && (
                  <p className="text-xs text-destructive">{tc("fieldRequired")}</p>
                )}
              </div>
            )
          })}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>{tc("cancel")}</Button>
          <Button onClick={submit} disabled={submitting}>
            {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {tc("save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
