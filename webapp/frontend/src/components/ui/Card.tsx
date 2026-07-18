import type { HTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  /**
   * 'surface' (default): opaque elevated card - used for repeated/list content
   * where a backdrop blur would hurt scroll performance and legibility.
   * 'glass': true translucent Liquid Glass material - reserve for standalone,
   * non-repeated surfaces (e.g. the login/setup card floating on the app wash).
   */
  variant?: 'surface' | 'glass'
}

export function Card({ className, variant = 'surface', ...props }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-2xl text-card-foreground',
        variant === 'glass'
          ? 'glass-surface-strong'
          : 'border border-border bg-card shadow-[0_1px_2px_rgba(0,0,0,0.06),0_8px_24px_-16px_rgba(0,0,0,0.25)]',
        className,
      )}
      {...props}
    />
  )
}

export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex flex-col gap-1.5 p-5', className)} {...props} />
}

export function CardTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn('text-lg font-semibold leading-none tracking-tight', className)} {...props} />
}

export function CardDescription({ className, ...props }: HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('text-sm text-muted-foreground', className)} {...props} />
}

export function CardContent({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-5 pt-0', className)} {...props} />
}

export function CardFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('flex items-center gap-2 p-5 pt-0', className)} {...props} />
}
