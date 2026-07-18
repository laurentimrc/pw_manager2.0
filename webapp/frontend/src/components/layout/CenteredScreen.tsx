import type { ReactNode } from 'react'
import { KeyRound } from 'lucide-react'
import { ThemeToggle } from '@/components/layout/ThemeToggle'

export function CenteredScreen({ children }: { children: ReactNode }) {
  return (
    <div className="app-shell flex min-h-screen flex-col">
      <header className="glass-surface sticky top-0 z-10 flex items-center justify-between rounded-none border-x-0 border-t-0 px-6 py-4">
        <div className="flex items-center gap-2">
          <KeyRound className="h-6 w-6 text-primary" />
          <span className="text-lg font-semibold">Password Manager Pro</span>
          <span className="ml-2 rounded-full bg-amber-500/15 px-2.5 py-0.5 text-xs font-semibold text-amber-700 dark:text-amber-300">
            Progetto a scopo didattico
          </span>
        </div>
        <ThemeToggle />
      </header>
      <main className="flex flex-1 items-center justify-center px-4 py-10">
        <div className="w-full max-w-md">{children}</div>
      </main>
    </div>
  )
}
