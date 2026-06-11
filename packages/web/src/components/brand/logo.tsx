// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// No "use client" directive: `useId` is a React 18+ hook that works in
// both server and client components. Marking this file client-only would
// turn every importing tree into a client boundary, which is overkill
// for a presentational SVG.
import { useId } from "react"
import { cn } from "@/lib/utils"

/**
 * Inline SVG of the NIS2 platform mark — the same artwork lives at
 * docs/public/logo.svg and docs/public/favicon.svg. Inlining here means
 * no extra network round-trip on first paint, zero risk of layout shift,
 * and the gradient renders identically across browsers.
 *
 * The double-check motif (one mark at full opacity, a second offset and
 * dimmed to 0.55) is intentional — it reads as a confirmation echo,
 * referencing the NIS2 directive's twin focus on cybersecurity *and*
 * resilience. Don't reduce it to a single mark without coordinating with
 * the docs/og-image artwork.
 *
 * `size` controls both width and height in pixels (the SVG is square).
 * Use Tailwind classes via `className` for spacing/positioning.
 */
export function Logo({
  size = 32,
  className,
}: {
  size?: number
  className?: string
}) {
  // The sidebar renders one Logo for mobile and one for desktop in the
  // same DOM. If both reference the same `#id`, browsers resolve the
  // url(#id) against the *first* occurrence — and if that one happens
  // to be inside a transformed/clipped subtree (mobile sidebar with
  // -translate-x-full), the gradient disappears on the desktop instance
  // too. `useId` produces a stable, SSR-safe, per-instance id.
  const reactId = useId()
  const gradientId = `nis2-logo-grad-${reactId.replace(/[:]/g, "")}`
  const titleId = `nis2-logo-title-${reactId.replace(/[:]/g, "")}`
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width={size}
      height={size}
      fill="none"
      // shrink-0 keeps the logo's intrinsic size inside flex parents
      // (the sidebar header is `flex items-center gap-2` — without
      // shrink-0 the SVG can collapse if the parent is constrained).
      className={cn("shrink-0", className)}
      // role + aria-label make this an image for screen readers; without
      // them the SVG is announced as a meaningless decorative blob.
      aria-labelledby={titleId}
      role="img"
      // Prevents the SVG from becoming a tab stop in legacy IE/Edge
      // engines — harmless on every modern browser.
      focusable="false"
    >
      <title id={titleId}>NIS2 Platform</title>
      <defs>
        <linearGradient
          id={gradientId}
          x1="0"
          y1="0"
          x2="64"
          y2="64"
          gradientUnits="userSpaceOnUse"
        >
          <stop offset="0" stopColor="#0071e3" />
          <stop offset="1" stopColor="#6e40c9" />
        </linearGradient>
      </defs>
      <circle cx="32" cy="32" r="30" fill={`url(#${gradientId})`} />
      <circle
        cx="32"
        cy="32"
        r="26"
        fill="none"
        stroke="#fff"
        strokeWidth="0.6"
        opacity="0.25"
      />
      {/* Back mark — dimmed echo */}
      <path
        d="M18 32l7 7 13-14"
        stroke="#fff"
        strokeWidth="5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
        opacity="0.55"
      />
      {/* Front mark — full opacity */}
      <path
        d="M26 32l7 7 13-14"
        stroke="#fff"
        strokeWidth="5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  )
}
