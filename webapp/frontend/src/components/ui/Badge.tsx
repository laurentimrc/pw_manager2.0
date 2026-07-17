import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/cn'

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        outline: 'border-border text-foreground',
        warning: 'border-transparent bg-warning/20 text-warning-foreground text-amber-700 dark:text-amber-300',
        destructive: 'border-transparent bg-destructive/15 text-destructive',
        success: 'border-transparent bg-success/15 text-emerald-700 dark:text-emerald-300',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}
