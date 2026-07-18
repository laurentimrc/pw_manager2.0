import { useRef, type ReactNode } from 'react'
import { KeyRound } from 'lucide-react'
import { ThemeToggle } from '@/components/layout/ThemeToggle'
import { useParallaxWash } from '@/hooks/useParallaxWash'

export function CenteredScreen({ children }: { children: ReactNode }) {
  const shellRef = useRef<HTMLDivElement>(null)
  useParallaxWash(shellRef)

  return (
    <div ref={shellRef} className="app-shell flex min-h-screen flex-col">
      <header className="sticky top-4 z-10 mx-4 flex items-center justify-between rounded-3xl px-5 py-3.5 glass-2 sm:mx-6">
        <div className="flex items-center gap-2.5">
          <span className="glass-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-2xl">
            <KeyRound className="h-4.5 w-4.5 text-primary" />
          </span>
          <span className="text-lg font-semibold">Password Manager Pro</span>
          <span className="ml-1 rounded-full bg-warning/20 px-2.5 py-0.5 text-xs font-semibold text-amber-800 dark:text-amber-300">
            Progetto a scopo didattico
          </span>
        </div>
        <ThemeToggle />
      </header>
      <main className="relative z-[1] flex flex-1 items-center justify-center px-4 py-10">
        <div className="w-full max-w-md">{children}</div>
      </main>
    </div>
  )
}
