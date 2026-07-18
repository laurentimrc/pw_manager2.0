import { forwardRef, type ButtonHTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/cn'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full text-sm font-medium ' +
    'transition-[background-color,border-color,color,box-shadow,filter] duration-150 ease-[var(--ease-standard)] ' +
    'motion-safe:transition-transform motion-safe:duration-150 motion-safe:ease-[var(--ease-spring)] ' +
    'active:scale-[0.96] disabled:pointer-events-none disabled:opacity-50 disabled:active:scale-100 ' +
    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 ' +
    'focus-visible:ring-offset-background',
  {
    variants: {
      variant: {
        default:
          'bg-primary text-primary-foreground shadow-[0_1px_2px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.3)] ' +
          'bg-[image:linear-gradient(160deg,oklch(1_0_0/0.16),transparent_55%)] ' +
          'hover:brightness-[1.06] hover:shadow-[0_4px_14px_-4px_var(--primary-glow),inset_0_1px_0_rgba(255,255,255,0.3)] ' +
          'active:brightness-95',
        destructive:
          'bg-destructive text-destructive-foreground shadow-[0_1px_2px_rgba(0,0,0,0.18),inset_0_1px_0_rgba(255,255,255,0.22)] ' +
          'bg-[image:linear-gradient(160deg,oklch(1_0_0/0.14),transparent_55%)] ' +
          'hover:brightness-[1.05] active:brightness-95',
        outline:
          'border border-border bg-background/60 backdrop-blur-sm hover:bg-accent hover:text-accent-foreground hover:border-transparent',
        secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/70',
        ghost: 'hover:bg-accent hover:text-accent-foreground',
        glass: 'glass-1 text-foreground hover:bg-accent/40',
        link: 'rounded-md text-primary underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-9 px-4 py-2',
        sm: 'h-8 px-3 text-xs',
        lg: 'h-11 px-6',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
)

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, ...props }, ref) => (
    <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  ),
)
Button.displayName = 'Button'
