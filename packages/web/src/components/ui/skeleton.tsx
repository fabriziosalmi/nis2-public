import { cn } from "@/lib/utils"

function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-md bg-muted relative overflow-hidden before:absolute before:inset-0 before:-translate-x-full before:animate-[shimmer_2s_infinite] before:bg-gradient-to-r before:from-transparent before:via-black/5 dark:before:via-white/10 before:to-transparent",
        className
      )}
      {...props}
    />
  )
}

function TableSkeleton({ columns = 5, rows = 5 }: { columns?: number, rows?: number }) {
  return (
    <div className="w-full">
      <div className="border-b">
        <div className="flex w-full items-center h-12 px-4 gap-4">
          {Array.from({ length: columns }).map((_, i) => (
            <Skeleton key={i} className="h-4 w-full" />
          ))}
        </div>
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex w-full items-center h-14 px-4 gap-4 border-b last:border-0">
          {Array.from({ length: columns }).map((_, c) => (
            <Skeleton key={c} className={`h-4 w-full ${c === 0 ? 'max-w-[150px]' : c === columns - 1 ? 'max-w-[80px]' : ''}`} />
          ))}
        </div>
      ))}
    </div>
  )
}

export { Skeleton, TableSkeleton }
