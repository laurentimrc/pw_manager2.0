import { Moon, Sun } from 'lucide-react'
import { useTheme } from '@/hooks/useTheme'
import { cn } from '@/lib/cn'

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme()
  const isDark = theme === 'dark'

  return (
    <button
      type="button"
      role="switch"
      aria-checked={isDark}
      onClick={toggleTheme}
      aria-label={isDark ? 'Passa al tema chiaro' : 'Passa al tema scuro'}
      title={isDark ? 'Tema chiaro' : 'Tema scuro'}
      className={cn(
        'relative inline-flex h-8 w-14 shrink-0 items-center rounded-full border border-border/60 px-1',
        'bg-muted/80 transition-colors duration-200 ease-[var(--ease-standard)]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
      )}
    >
      <Sun className="absolute left-1.5 h-3.5 w-3.5 text-amber-500/70" aria-hidden />
      <Moon className="absolute right-1.5 h-3.5 w-3.5 text-indigo-300/70 dark:text-indigo-200/80" aria-hidden />
      <span
        className={cn(
          'relative z-10 flex h-6 w-6 items-center justify-center rounded-full bg-card text-foreground',
          'shadow-[0_1px_3px_rgba(0,0,0,0.3),inset_0_1px_0_rgba(255,255,255,0.5)]',
          'motion-safe:transition-transform motion-safe:duration-[380ms] motion-safe:ease-[var(--ease-spring)]',
          isDark ? 'translate-x-6' : 'translate-x-0',
        )}
      >
        {isDark ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5 text-amber-500" />}
      </span>
    </button>
  )
}
