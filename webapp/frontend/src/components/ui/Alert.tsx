import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { AlertCircle, AlertTriangle, CheckCircle2, Info } from 'lucide-react'
import { cn } from '@/lib/cn'

const alertVariants = cva('flex items-start gap-2.5 rounded-2xl border p-3.5 text-sm animate-spring-in', {
  variants: {
    variant: {
      default: 'border-border bg-muted text-foreground',
      destructive: 'border-destructive/25 bg-destructive/10 text-red-700 dark:text-red-400',
      success: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300',
      warning: 'border-amber-500/25 bg-amber-500/10 text-amber-800 dark:text-amber-300',
      info: 'border-sky-500/25 bg-sky-500/10 text-sky-800 dark:text-sky-300',
    },
  },
  defaultVariants: { variant: 'default' },
})

const ICONS = {
  default: Info,
  destructive: AlertCircle,
  success: CheckCircle2,
  warning: AlertTriangle,
  info: Info,
} as const

export interface AlertProps extends HTMLAttributes<HTMLDivElement>, VariantProps<typeof alertVariants> {
  /** Set to false to omit the leading variant icon (e.g. for very dense/nested alerts). */
  icon?: boolean
}

export function Alert({ className, variant, icon = true, children, ...props }: AlertProps) {
  const resolvedVariant = variant ?? 'default'
  const Icon = ICONS[resolvedVariant]
  return (
    <div role="alert" className={cn(alertVariants({ variant }), className)} {...props}>
      {icon && <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />}
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  )
}
