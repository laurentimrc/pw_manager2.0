import { createContext, useContext, useState, type ReactNode } from 'react'
import { useSlidingIndicator } from '@/hooks/useSlidingIndicator'
import { cn } from '@/lib/cn'

interface TabsContextValue {
  value: string
  setValue: (value: string) => void
}

const TabsContext = createContext<TabsContextValue | null>(null)

export function Tabs({
  defaultValue,
  children,
  className,
}: {
  defaultValue: string
  children: ReactNode
  className?: string
}) {
  const [value, setValue] = useState(defaultValue)
  return (
    <TabsContext.Provider value={{ value, setValue }}>
      <div className={className}>{children}</div>
    </TabsContext.Provider>
  )
}

export function TabsList({ children, className }: { children: ReactNode; className?: string }) {
  const ctx = useContext(TabsContext)
  if (!ctx) throw new Error('TabsList deve essere usato dentro <Tabs>')
  const { containerRef, indicatorRect, indicatorReady } = useSlidingIndicator<HTMLDivElement>(ctx.value)

  return (
    <div
      ref={containerRef}
      className={cn(
        'relative inline-flex h-10 items-center justify-center gap-0.5 rounded-full bg-muted p-1 text-muted-foreground',
        className,
      )}
    >
      {indicatorRect && (
        <span
          aria-hidden
          className={cn(
            'pointer-events-none absolute left-0 top-0 z-0 rounded-full bg-card shadow-sm',
            indicatorReady && 'transition-[transform,width] duration-[380ms] ease-[var(--ease-spring)]',
          )}
          style={{
            width: indicatorRect.width,
            height: indicatorRect.height,
            transform: `translate3d(${indicatorRect.left}px, ${indicatorRect.top}px, 0)`,
          }}
        />
      )}
      {children}
    </div>
  )
}

export function TabsTrigger({ value, children }: { value: string; children: ReactNode }) {
  const ctx = useContext(TabsContext)
  if (!ctx) throw new Error('TabsTrigger deve essere usato dentro <Tabs>')
  const isActive = ctx.value === value
  return (
    <button
      type="button"
      data-key={value}
      onClick={() => ctx.setValue(value)}
      className={cn(
        'relative z-10 inline-flex items-center justify-center whitespace-nowrap rounded-full px-3.5 py-1.5 text-sm font-medium',
        'transition-colors duration-150 ease-[var(--ease-standard)] active:scale-[0.97] motion-safe:transition-transform',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        isActive ? 'text-foreground' : 'hover:text-foreground',
      )}
    >
      {children}
    </button>
  )
}

export function TabsContent({ value, children }: { value: string; children: ReactNode }) {
  const ctx = useContext(TabsContext)
  if (!ctx) throw new Error('TabsContent deve essere usato dentro <Tabs>')
  if (ctx.value !== value) return null
  return (
    <div className="mt-4 animate-spring-in" key={value}>
      {children}
    </div>
  )
}
