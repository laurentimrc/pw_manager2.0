import { KeyRound, LayoutList, Lock, PlusCircle, Settings, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ThemeToggle } from '@/components/layout/ThemeToggle'
import { useSlidingIndicator } from '@/hooks/useSlidingIndicator'
import { cn } from '@/lib/cn'

export type View = 'list' | 'add' | 'dashboard' | 'utility'

const NAV_ITEMS: { view: View; label: string; icon: typeof LayoutList }[] = [
  { view: 'list', label: 'Visualizza / Modifica', icon: LayoutList },
  { view: 'add', label: 'Aggiungi Nuova', icon: PlusCircle },
  { view: 'dashboard', label: 'Dashboard Sicurezza', icon: ShieldCheck },
  { view: 'utility', label: 'Utility', icon: Settings },
]

export function Sidebar({
  view,
  onChangeView,
  credentialCount,
  onLock,
}: {
  view: View
  onChangeView: (view: View) => void
  credentialCount: number
  onLock: () => void
}) {
  const { containerRef, indicatorRect, indicatorReady } = useSlidingIndicator<HTMLElement>(view)

  return (
    <aside className="glass-2 sticky top-4 flex h-[calc(100vh-2rem)] w-64 shrink-0 flex-col gap-6 rounded-3xl p-4">
      <div>
        <div className="flex items-center gap-2.5 px-1">
          <span className="glass-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-2xl">
            <KeyRound className="h-4.5 w-4.5 text-primary" />
          </span>
          <span className="font-semibold leading-tight">Password Manager Pro</span>
        </div>
        <div className="mt-3 flex items-center gap-2 rounded-2xl bg-success/12 px-3 py-2 text-sm font-medium text-emerald-800 dark:text-emerald-300">
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-500 shadow-[0_0_0_3px_oklch(0.6_0.15_145/0.2)]" />
          Accesso eseguito
        </div>
        <p className="mt-2 px-1 text-xs text-muted-foreground">{credentialCount} credenziali salvate</p>
      </div>

      <nav ref={containerRef} className="relative flex flex-col gap-1">
        {indicatorRect && (
          <span
            aria-hidden
            className={cn(
              'pointer-events-none absolute left-0 top-0 z-0 rounded-2xl bg-primary',
              'shadow-[0_1px_2px_rgba(0,0,0,0.15),inset_0_1px_0_rgba(255,255,255,0.25)]',
              indicatorReady && 'transition-[transform,width,height] duration-[420ms] ease-[var(--ease-spring)]',
            )}
            style={{
              width: indicatorRect.width,
              height: indicatorRect.height,
              transform: `translate3d(${indicatorRect.left}px, ${indicatorRect.top}px, 0)`,
            }}
          />
        )}
        {NAV_ITEMS.map(({ view: itemView, label, icon: Icon }) => (
          <button
            key={itemView}
            type="button"
            data-key={itemView}
            onClick={() => onChangeView(itemView)}
            data-testid={`nav-${itemView}`}
            className={cn(
              'relative z-10 flex items-center gap-2 rounded-2xl px-3 py-2 text-left text-sm font-medium',
              'transition-[color,transform] duration-150 ease-[var(--ease-standard)] active:scale-[0.98]',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
              view === itemView
                ? 'text-primary-foreground'
                : 'text-foreground hover:bg-accent/70 hover:text-accent-foreground',
            )}
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </button>
        ))}
      </nav>

      <div className="mt-auto flex flex-col gap-3">
        <Button variant="destructive" onClick={onLock} data-testid="lock-app-button">
          <Lock className="h-4 w-4" />
          Blocca App
        </Button>
        <div className="flex justify-center">
          <ThemeToggle />
        </div>
      </div>
    </aside>
  )
}
