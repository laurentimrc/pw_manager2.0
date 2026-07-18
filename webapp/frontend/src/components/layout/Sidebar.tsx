import { KeyRound, LayoutList, Lock, PlusCircle, Settings, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ThemeToggle } from '@/components/layout/ThemeToggle'
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
  return (
    <aside className="glass-surface sticky top-0 flex h-screen w-64 shrink-0 flex-col gap-6 rounded-none border-y-0 border-l-0 p-4">
      <div>
        <div className="flex items-center gap-2 px-1">
          <KeyRound className="h-5 w-5 text-primary" />
          <span className="font-semibold">Password Manager Pro</span>
        </div>
        <div className="mt-3 flex items-center justify-between rounded-xl bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-300">
          <span>Accesso eseguito</span>
        </div>
        <p className="mt-2 px-1 text-xs text-muted-foreground">{credentialCount} credenziali salvate</p>
      </div>

      <nav className="flex flex-col gap-1">
        {NAV_ITEMS.map(({ view: itemView, label, icon: Icon }) => (
          <button
            key={itemView}
            type="button"
            onClick={() => onChangeView(itemView)}
            data-testid={`nav-${itemView}`}
            className={cn(
              'flex items-center gap-2 rounded-xl px-3 py-2 text-left text-sm font-medium',
              'transition-[background-color,color,transform] duration-150 ease-[cubic-bezier(0.34,1.56,0.64,1)] active:scale-[0.98]',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
              view === itemView
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-foreground hover:bg-accent hover:text-accent-foreground',
            )}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </nav>

      <div className="mt-auto flex flex-col gap-2">
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
