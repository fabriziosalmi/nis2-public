// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// The first tests in this package.
//
// 13,618 lines of TypeScript were verified only by `tsc` and ESLint — neither of
// which can tell whether a countdown counts down. What is covered here first is
// the Art. 23 deadline arithmetic, because it is the logic in this package with
// legal consequences: it decides whether an operator is told a statutory
// obligation is due in four hours or was missed yesterday.

import { describe, expect, it } from "vitest"

import {
  URGENT_WINDOW_MS,
  deadlineState,
  formatRemaining,
  type Deadline,
} from "../deadlines"

const NOW = Date.UTC(2026, 2, 1, 12, 0, 0)
const at = (offsetMs: number) => new Date(NOW + offsetMs).toISOString()

const due = (offsetMs: number, sentAt: string | null = null): Deadline => ({
  label: "early_warning",
  deadline: at(offsetMs),
  sent_at: sentAt,
})

describe("deadlineState", () => {
  it("returns null when there is no deadline", () => {
    // A final report has none until the notification is filed. Rendering a
    // countdown to nothing would be worse than rendering nothing.
    expect(
      deadlineState({ label: "final_report", deadline: null, sent_at: null }, true, NOW),
    ).toBeNull()
  })

  it("counts down while the deadline is ahead", () => {
    const state = deadlineState(due(4 * 3600_000), true, NOW)!
    expect(state.remainingMs).toBe(4 * 3600_000)
    expect(state.overdue).toBe(false)
  })

  it("goes negative once the deadline has passed", () => {
    const state = deadlineState(due(-90 * 60_000), true, NOW)!
    expect(state.remainingMs).toBe(-90 * 60_000)
    expect(state.overdue).toBe(true)
  })

  it("is urgent inside the warning window and not outside it", () => {
    expect(deadlineState(due(URGENT_WINDOW_MS - 1), true, NOW)!.urgent).toBe(true)
    expect(deadlineState(due(URGENT_WINDOW_MS + 1), true, NOW)!.urgent).toBe(false)
  })

  it("treats the exact boundary as not yet urgent", () => {
    // Exactly six hours out is the far edge of the window, not inside it.
    expect(deadlineState(due(URGENT_WINDOW_MS), true, NOW)!.urgent).toBe(false)
  })

  it("treats the deadline instant as not yet overdue", () => {
    const state = deadlineState(due(0), true, NOW)!
    expect(state.overdue).toBe(false)
    expect(state.urgent).toBe(true)
  })

  it("never flags a filed obligation, however late", () => {
    // Recording the submission is what stops the alerting. If a filed
    // obligation still showed as overdue, the operator would have no way to
    // clear it and the display would contradict the deadline monitor.
    const state = deadlineState(due(-30 * 86400_000, at(-29 * 86400_000)), true, NOW)!
    expect(state.sent).toBe(true)
    expect(state.overdue).toBe(false)
    expect(state.urgent).toBe(false)
  })

  it("never flags a closed incident", () => {
    // The clock has stopped. Flagging it would be a false alarm for ever.
    const state = deadlineState(due(-5 * 86400_000), false, NOW)!
    expect(state.overdue).toBe(false)
    expect(state.urgent).toBe(false)
    expect(state.remainingMs).toBeLessThan(0)
  })
})

describe("formatRemaining", () => {
  it("formats under a day without a day component", () => {
    expect(formatRemaining(4 * 3600_000 + 5 * 60_000 + 9_000)).toBe("04:05:09")
  })

  it("includes days once there are any", () => {
    expect(formatRemaining(29 * 86400_000 + 23 * 3600_000 + 58 * 60_000 + 29_000)).toBe(
      "29d 23:58:29",
    )
  })

  it("signs an overdue interval rather than clamping it to zero", () => {
    // "-04:12:07" tells an operator how badly the deadline was missed;
    // "00:00:00" tells them nothing.
    expect(formatRemaining(-(4 * 3600_000 + 12 * 60_000 + 7_000))).toBe("-04:12:07")
  })

  it("pads every component to two digits", () => {
    expect(formatRemaining(60_000 + 1_000)).toBe("00:01:01")
  })

  it("renders zero as zero, unsigned", () => {
    expect(formatRemaining(0)).toBe("00:00:00")
  })

  it("truncates sub-second remainder rather than rounding up", () => {
    // Rounding up would briefly show one second remaining after the deadline
    // had actually passed.
    expect(formatRemaining(1_999)).toBe("00:00:01")
  })
})
