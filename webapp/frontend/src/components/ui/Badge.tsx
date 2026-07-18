import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/cn'

const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-tight transition-colors',
  {
    variants: {
      variant: {
        default:
          'border-transparent bg-primary text-primary-foreground bg-[image:linear-gradient(160deg,oklch(1_0_0/0.18),transparent_60%)]',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        outline: 'border-border text-foreground',
        warning: 'border-amber-500/20 bg-amber-500/15 text-amber-800 dark:border-amber-400/25 dark:text-amber-300',
        destructive:
          'border-destructive/20 bg-destructive/15 text-red-700 dark:border-destructive/30 dark:text-red-400',
        success:
          'border-emerald-500/20 bg-emerald-500/15 text-emerald-800 dark:border-emerald-400/25 dark:text-emerald-300',
      },
    },
    defaultVariants: { variant: 'default' },
  },
)

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}
