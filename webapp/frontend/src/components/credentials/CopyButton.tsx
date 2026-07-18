import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/cn'

export function CopyButton({
  getValue,
  label,
}: {
  getValue: () => Promise<string> | string
  label: string
}) {
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState(false)

  async function handleCopy() {
    try {
      const value = await getValue()
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setError(false)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setError(true)
      setTimeout(() => setError(false), 1500)
    }
  }

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={handleCopy}
      aria-label={label}
      title={label}
      className={cn(
        copied && 'border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300',
        error && 'border-destructive/30 bg-destructive/10 text-red-700 dark:text-red-400',
      )}
    >
      {copied ? (
        <Check className="h-3.5 w-3.5 animate-spring-in" key="check" />
      ) : (
        <Copy className="h-3.5 w-3.5" key="copy" />
      )}
      {copied ? 'Copiato!' : error ? 'Errore' : 'Copia'}
    </Button>
  )
}
