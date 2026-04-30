// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// v2.4.17 audit S-DRA-02: debounce a value so React Query queries
// don't refire on every keystroke / dropdown click.
//
// The findings table previously called `setSeverityFilter` /
// `setStatusFilter` / `setCategoryFilter` directly from the Select
// onChange handlers. A user clicking through three dropdowns in a
// row fired three concurrent /api/v1/findings requests, with no
// guarantee of arrival order — so the rendered list could end up
// reflecting the SECOND click's filters rather than the third.
// Debouncing the params before they hit `useFindings` collapses
// rapid changes into a single trailing fetch.
//
// 250ms is the common UX sweet spot — shorter feels twitchy on
// keystroke filters, longer feels laggy on dropdown clicks.

"use client"

import { useEffect, useState } from "react"

export function useDebounce<T>(value: T, delayMs = 250): T {
  const [debounced, setDebounced] = useState(value)

  useEffect(() => {
    const handle = setTimeout(() => setDebounced(value), delayMs)
    // Cancellation is the whole point: every value change resets the
    // timer, so only the last value within the quiet window
    // actually propagates. The cleanup clears the previous timer
    // before the new one starts.
    return () => clearTimeout(handle)
  }, [value, delayMs])

  return debounced
}
