// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public

"use client"

import { useEffect, useState } from "react"
import { motion, useSpring, useTransform } from "framer-motion"

interface AnimatedCounterProps {
  value: number
  className?: string
  format?: (value: number) => string
}

export function AnimatedCounter({
  value,
  className,
  format = (v) => Math.round(v).toString(),
}: AnimatedCounterProps) {
  // Use a spring physics model for organic deceleration
  const springValue = useSpring(0, {
    bounce: 0,
    duration: 1200,
  })

  useEffect(() => {
    springValue.set(value)
  }, [springValue, value])

  // Transform the spring's continuous value into the formatted string
  const displayValue = useTransform(springValue, (current) => format(current))

  return <motion.span className={className}>{displayValue}</motion.span>
}