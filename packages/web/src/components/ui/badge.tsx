// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary: "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive: "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        outline: "text-foreground",
        critical: "border-red-500/30 bg-red-500/15 text-red-700 dark:bg-red-500/20 dark:text-red-300 dark:border-red-500/30",
        high: "border-orange-500/30 bg-orange-500/15 text-orange-800 dark:bg-orange-500/20 dark:text-orange-300 dark:border-orange-500/30",
        medium: "border-amber-500/30 bg-amber-500/15 text-amber-900 dark:bg-amber-500/20 dark:text-amber-300 dark:border-amber-500/30",
        low: "border-blue-500/30 bg-blue-500/15 text-blue-800 dark:bg-blue-500/20 dark:text-blue-300 dark:border-blue-500/30",
        info: "border-muted-foreground/30 bg-muted text-muted-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
