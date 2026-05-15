"use client"

import { useState } from "react"
import { Check, Copy } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"

interface CopyToClipboardProps {
  value: string
  className?: string
  iconSize?: number
}

export function CopyToClipboard({ value, className, iconSize = 14 }: CopyToClipboardProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async (e: React.MouseEvent) => {
    e.stopPropagation()
    e.preventDefault()
    if (!value) return
    
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error("Failed to copy text: ", err)
    }
  }

  return (
    <Button
      variant="ghost"
      size="icon"
      className={cn("h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity", className)}
      onClick={handleCopy}
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="text-green-500" size={iconSize} />
      ) : (
        <Copy className="text-muted-foreground hover:text-foreground" size={iconSize} />
      )}
      <span className="sr-only">Copy</span>
    </Button>
  )
}
