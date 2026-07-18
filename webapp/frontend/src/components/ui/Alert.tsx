import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/cn'

const alertVariants = cva('flex items-start gap-2 rounded-xl border p-3.5 text-sm animate-spring-in', {
  variants: {
    variant: {
      default: 'border-border bg-muted text-foreground',
      destructive: 'border-destructive/30 bg-destructive/10 text-destructive',
      success: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
      warning: 'border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300',
      info: 'border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300',
    },
  },
  defaultVariants: { variant: 'default' },
})

export interface AlertProps extends HTMLAttributes<HTMLDivElement>, VariantProps<typeof alertVariants> {}

export function Alert({ className, variant, ...props }: AlertProps) {
  return <div role="alert" className={cn(alertVariants({ variant }), className)} {...props} />
}
