import { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { Button } from '@/components/ui/Button'
import { CopyButton } from '@/components/credentials/CopyButton'

const RADIUS = 15
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function urgencyColor(fraction: number): string {
  if (fraction <= 0.17) return 'var(--destructive)'
  if (fraction <= 0.4) return 'var(--warning)'
  return 'var(--success)'
}

function CountdownRing({ remaining, period }: { remaining: number; period: number }) {
  const fraction = period > 0 ? remaining / period : 0
  const offset = CIRCUMFERENCE * (1 - fraction)
  const color = urgencyColor(fraction)

  return (
    <svg width="36" height="36" viewBox="0 0 36 36" className="shrink-0 -rotate-90" aria-hidden>
      <circle cx="18" cy="18" r={RADIUS} strokeWidth="3" className="stroke-muted" fill="none" />
      <circle
        cx="18"
        cy="18"
        r={RADIUS}
        strokeWidth="3"
        stroke={color}
        fill="none"
        strokeLinecap="round"
        strokeDasharray={CIRCUMFERENCE}
        strokeDashoffset={offset}
        style={{ transition: 'stroke-dashoffset 1s linear, stroke 0.3s var(--ease-standard)' }}
      />
    </svg>
  )
}

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
      <div className="flex items-center gap-3">
        <CountdownRing remaining={remaining} period={period} />
        <code className="glass-1 rounded-2xl px-3.5 py-2 text-lg font-mono font-medium tracking-[0.2em] tabular-nums">
          {code ?? '------'}
        </code>
        <CopyButton label="Copia codice 2FA" getValue={() => code ?? ''} />
        <Button type="button" variant="ghost" size="icon" onClick={fetchCode} title="Aggiorna codice" aria-label="Aggiorna codice">
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </div>
      <span className="text-xs text-muted-foreground">Nuovo codice tra {remaining}s</span>
    </div>
  )
}
