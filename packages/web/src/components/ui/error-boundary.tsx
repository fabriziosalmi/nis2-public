// Copyright (c) 2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
"use client"

import { Component, type ErrorInfo, type ReactNode } from "react"
import { AlertTriangle, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ErrorBoundaryProps {
  /** Fallback UI override — renders instead of the default card. */
  fallback?: (error: Error, reset: () => void) => ReactNode
  /** Content to protect. */
  children: ReactNode
}

interface ErrorBoundaryState {
  error: Error | null
}

// ---------------------------------------------------------------------------
// Class component — React error boundaries must be class components.
// ---------------------------------------------------------------------------

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Log to the browser console so developers see the full stack in
    // DevTools. In production, replace this with your error-reporting
    // service (Sentry, Datadog RUM, etc.) if you add one.
    console.error("[ErrorBoundary] Uncaught error:", error, info.componentStack)
  }

  reset = (): void => {
    this.setState({ error: null })
  }

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children

    if (this.props.fallback) {
      return this.props.fallback(error, this.reset)
    }

    return <DefaultErrorCard error={error} reset={this.reset} />
  }
}

// ---------------------------------------------------------------------------
// Default fallback UI
// ---------------------------------------------------------------------------

function DefaultErrorCard({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="flex min-h-[200px] items-center justify-center p-6">
      <Card className="w-full max-w-md border-destructive/40">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="h-5 w-5 shrink-0" />
            Something went wrong
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          <p>An unexpected error occurred in this section of the page.</p>
          {process.env.NODE_ENV !== "production" && (
            <pre className="mt-3 max-h-32 overflow-auto rounded bg-muted p-2 text-xs text-foreground">
              {error.message}
            </pre>
          )}
        </CardContent>
        <CardFooter>
          <Button variant="outline" size="sm" onClick={reset} className="gap-2">
            <RefreshCw className="h-3.5 w-3.5" />
            Try again
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Convenience wrapper for common use — wraps a single section.
// ---------------------------------------------------------------------------

export function withErrorBoundary(
  children: ReactNode,
  fallback?: (error: Error, reset: () => void) => ReactNode,
): ReactNode {
  return <ErrorBoundary fallback={fallback}>{children}</ErrorBoundary>
}
