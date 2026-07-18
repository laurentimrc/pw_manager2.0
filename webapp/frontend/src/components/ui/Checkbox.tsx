import { forwardRef, type InputHTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

export const Checkbox = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      type="checkbox"
      ref={ref}
      className={cn(
        'h-4.5 w-4.5 shrink-0 cursor-pointer rounded-[6px] border border-input accent-[var(--primary)]',
        'transition-[box-shadow,transform] duration-150 ease-[var(--ease-standard)] active:scale-90',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background',
        className,
      )}
      {...props}
    />
  ),
)
Checkbox.displayName = 'Checkbox'
