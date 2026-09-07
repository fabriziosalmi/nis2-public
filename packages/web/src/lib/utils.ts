// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** The message to show a user for a thrown value.
 *
 *  `catch (err: any) { err.message }` is the idiom throughout this codebase and
 *  it is two bets at once: that what was thrown is an object, and that the
 *  object has a `message`. A thrown string renders as `undefined`. This narrows
 *  instead, and gives new code a way to stay out of the `any` count the review
 *  is about. */
export function errorMessage(err: unknown, fallback = "Unexpected error"): string {
  if (err instanceof Error && err.message) return err.message
  if (typeof err === "string" && err) return err
  return fallback
}
