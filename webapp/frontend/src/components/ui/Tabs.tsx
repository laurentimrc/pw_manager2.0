import { createContext, useContext, useState, type ReactNode } from 'react'
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
  return (
    <div
      className={cn(
        'inline-flex h-9 items-center justify-center rounded-lg bg-muted p-1 text-muted-foreground',
        className,
      )}
    >
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
      onClick={() => ctx.setValue(value)}
      className={cn(
        'inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium',
        'transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        isActive ? 'bg-card text-foreground shadow-sm' : 'hover:text-foreground',
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
  return <div className="mt-4">{children}</div>
}
