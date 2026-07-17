import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

export const Checkbox = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      type="checkbox"
      ref={ref}
      className={cn(
        'h-4 w-4 shrink-0 rounded border border-input accent-[var(--primary)]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        className,
      )}
      {...props}
    />
  ),
)
Checkbox.displayName = 'Checkbox'
