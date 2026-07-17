import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@/components/ui/Button'

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
    <Button type="button" variant="outline" size="sm" onClick={handleCopy} aria-label={label} title={label}>
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copiato!' : error ? 'Errore' : 'Copia'}
    </Button>
  )
}
