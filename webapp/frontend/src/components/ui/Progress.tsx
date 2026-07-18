import { cn } from '@/lib/cn'

interface ProgressProps {
  value: number // 0-100
  className?: string
  indicatorClassName?: string
}

export function Progress({ value, className, indicatorClassName }: ProgressProps) {
  return (
    <div className={cn('h-2 w-full overflow-hidden rounded-full bg-muted', className)}>
      <div
        className={cn(
          'h-full rounded-full transition-[width,background-color] duration-300 ease-[var(--ease-standard)]',
          indicatorClassName ?? 'bg-primary',
        )}
        style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
      />
    </div>
  )
}
