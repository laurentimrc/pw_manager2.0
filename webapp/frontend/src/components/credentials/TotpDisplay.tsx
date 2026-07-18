import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { Progress } from '@/components/ui/Progress'
import { Button } from '@/components/ui/Button'
import { CopyButton } from '@/components/credentials/CopyButton'

export function TotpDisplay({ service }: { service: string }) {
  const [code, setCode] = useState<string | null>(null)
  const [remaining, setRemaining] = useState(0)
  const [period, setPeriod] = useState(30)
  const [error, setError] = useState<string | null>(null)

  async function fetchCode() {
    try {
      const info = await api.getCredentialTotp(service)
      setCode(info.code)
      setRemaining(info.remaining)
      setPeriod(info.period)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore nella generazione del codice TOTP.')
    }
  }

  useEffect(() => {
    fetchCode()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [service])

  useEffect(() => {
    if (code === null) return
    const timer = setInterval(() => {
      setRemaining((prev) => {
        if (prev <= 1) {
          fetchCode()
          return 0
        }
        return prev - 1
      })
    }, 1000)
    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [code])

  if (error) {
    return <p className="text-sm text-destructive">{error}</p>
  }

  return (
    <div className="flex flex-col gap-1.5" data-testid="totp-display">
      <span className="text-xs font-medium text-muted-foreground">Codice 2FA</span>
      <div className="flex items-center gap-2">
        <code className="rounded-xl bg-muted px-3 py-1.5 text-base font-mono tracking-widest">{code ?? '------'}</code>
        <CopyButton label="Copia codice 2FA" getValue={() => code ?? ''} />
        <Button type="button" variant="ghost" size="icon" onClick={fetchCode} title="Aggiorna codice" aria-label="Aggiorna codice">
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </div>
      <Progress value={(remaining / period) * 100} />
      <span className="text-xs text-muted-foreground">Nuovo codice tra {remaining}s</span>
    </div>
  )
}
