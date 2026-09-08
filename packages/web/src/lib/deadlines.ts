// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// Art. 23 countdown arithmetic, extracted from the incidents page so it can be
// tested.
//
// This logic decides what an operator is told about a statutory deadline: how
// long is left, whether it has passed, and whether it is close enough to be
// urgent. It lived inside a React component, which meant 13,618 lines of
// TypeScript had no tests and this — the part with legal consequences — was
// verified only by `tsc`, which can confirm the shapes line up and nothing about
// whether a countdown counts down.

/** One Art. 23 obligation as the API reports it. */
export interface Deadline {
  label: string
  deadline: string | null
  sent_at: string | null
}

/** What the UI needs to render one deadline chip. */
export interface DeadlineState {
  /** Signed milliseconds until the deadline; negative once it has passed. */
  remainingMs: number
  /** The obligation was filed. Nothing is chased for it any more. */
  sent: boolean
  /** Open, unfiled, and the deadline has passed. */
  overdue: boolean
  /** Open, unfiled, not yet passed, and inside the warning window. */
  urgent: boolean
}

/** How close to a deadline counts as urgent. */
export const URGENT_WINDOW_MS = 6 * 3600_000

/**
 * Derive the state of one deadline at a point in time.
 *
 * Returns null when there is no deadline to show — a final report has none
 * until the notification is filed, and rendering a countdown to nothing would
 * be worse than rendering nothing.
 *
 * A closed incident is never overdue or urgent: the clock has stopped and the
 * obligation is discharged, so flagging it would be a false alarm for ever.
 */
export function deadlineState(
  deadline: Deadline,
  isOpen: boolean,
  nowMs: number,
): DeadlineState | null {
  if (!deadline.deadline) return null

  const remainingMs = new Date(deadline.deadline).getTime() - nowMs
  const sent = !!deadline.sent_at

  return {
    remainingMs,
    sent,
    overdue: isOpen && !sent && remainingMs < 0,
    urgent: isOpen && !sent && remainingMs >= 0 && remainingMs < URGENT_WINDOW_MS,
  }
}

/**
 * Format a signed millisecond delta as `Dd HH:MM:SS`, or `HH:MM:SS` under a day.
 *
 * Signed on purpose: an overdue obligation shows how far past it is, because
 * "-04:12:07" tells an operator something that "00:00:00" does not.
 */
export function formatRemaining(ms: number): string {
  const negative = ms < 0
  let s = Math.floor(Math.abs(ms) / 1000)
  const d = Math.floor(s / 86400)
  s %= 86400
  const h = Math.floor(s / 3600)
  s %= 3600
  const m = Math.floor(s / 60)
  s %= 60
  const pad = (n: number) => String(n).padStart(2, "0")
  const core =
    d > 0 ? `${d}d ${pad(h)}:${pad(m)}:${pad(s)}` : `${pad(h)}:${pad(m)}:${pad(s)}`
  return (negative ? "-" : "") + core
}
