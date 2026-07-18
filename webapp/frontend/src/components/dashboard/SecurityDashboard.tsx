import { useEffect, useState } from 'react'
import {
  Clock3,
  KeyRound,
  RefreshCcw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ShieldQuestion,
  type LucideIcon,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Alert } from '@/components/ui/Alert'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { api, ApiError } from '@/lib/api'
import { cn } from '@/lib/cn'
import type { BreachCheckResult, SecurityDashboard as SecurityDashboardData } from '@/types'

function Metric({
  label,
  value,
  icon: Icon,
  tone,
}: {
  label: string
  value: number
  icon: LucideIcon
  tone: 'primary' | 'destructive' | 'warning' | 'success'
}) {
  const toneClass: Record<typeof tone, string> = {
    primary: 'text-primary bg-primary/10',
    destructive: 'text-destructive bg-destructive/10',
    warning: 'text-amber-600 bg-amber-500/12 dark:text-amber-300',
    success: 'text-emerald-600 bg-emerald-500/12 dark:text-emerald-300',
  }
  return (
    <Card className="flex flex-col gap-3 p-4">
      <span className={cn('flex h-8 w-8 items-center justify-center rounded-xl', toneClass[tone])}>
        <Icon className="h-4 w-4" />
      </span>
      <div>
        <span className="block text-2xl font-semibold tracking-tight">{value}</span>
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
      </div>
    </Card>
  )
}

/** Riga di risultato per una singola credenziale nel controllo violazioni.
 * `checked: false` (controllo non riuscito, es. rete assente) è mostrato in
 * modo visivamente distinto da "nessuna violazione trovata": sono
 * informazioni molto diverse e non vanno confuse. */
function BreachResultRow({
  result,
  retrying,
  onRetry,
}: {
  result: BreachCheckResult
  retrying: boolean
  onRetry: () => void
}) {
  const badge = !result.checked ? (
    <Badge variant="outline" className="gap-1" data-testid={`breach-status-${result.service}`}>
      <ShieldQuestion className="h-3 w-3" /> Controllo non riuscito
    </Badge>
  ) : (result.breach_count ?? 0) > 0 ? (
    <Badge variant="destructive" className="gap-1" data-testid={`breach-status-${result.service}`}>
      <ShieldOff className="h-3 w-3" /> Trovata in {result.breach_count} violazioni note
    </Badge>
  ) : (
    <Badge variant="success" className="gap-1" data-testid={`breach-status-${result.service}`}>
      <ShieldCheck className="h-3 w-3" /> Nessuna violazione nota
    </Badge>
  )

  return (
    <div
      className="flex flex-wrap items-center justify-between gap-2 rounded-2xl border border-border/60 px-3.5 py-2.5"
      data-testid={`breach-result-${result.service}`}
    >
      <span className="text-sm font-medium">{result.service}</span>
      <span className="flex items-center gap-2">
        {badge}
        {!result.checked && (
          <Button type="button" variant="outline" size="sm" onClick={onRetry} disabled={retrying}>
            {retrying ? 'Riprovo...' : 'Riprova'}
          </Button>
        )}
      </span>
    </div>
  )
}

function BreachCheckCard() {
  const [results, setResults] = useState<Record<string, BreachCheckResult>>({})
  const [checking, setChecking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [retryingService, setRetryingService] = useState<string | null>(null)

  const orderedResults = Object.values(results).sort((a, b) => a.service.localeCompare(b.service))
  const hasResults = orderedResults.length > 0
  const breachedCount = orderedResults.filter((r) => (r.breach_count ?? 0) > 0).length
  const failedCount = orderedResults.filter((r) => !r.checked).length

  async function handleCheckAll() {
    setChecking(true)
    setError(null)
    try {
      const response = await api.checkAllCredentialsBreach()
      const map: Record<string, BreachCheckResult> = {}
      for (const result of response.results) map[result.service] = result
      setResults(map)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il controllo delle violazioni.')
    } finally {
      setChecking(false)
    }
  }

  async function handleRetry(service: string) {
    setRetryingService(service)
    try {
      const result = await api.checkCredentialBreach(service)
      setResults((prev) => ({ ...prev, [service]: result }))
    } catch {
      // Il controllo resta segnato come "non riuscito" (`checked: false`):
      // l'utente può riprovare di nuovo.
    } finally {
      setRetryingService(null)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ScanSearch className="h-4 w-4" /> Controllo Violazioni Note (Have I Been Pwned)
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <Alert variant="info">
          Il controllo contatta l&apos;API pubblica Have I Been Pwned usando il modello k-anonymity: solo un
          prefisso di 5 caratteri dell&apos;hash della password viene inviato in rete, mai la password
          completa. Va avviato manualmente perché usa un servizio di terze parti.
        </Alert>

        <Button
          type="button"
          onClick={handleCheckAll}
          disabled={checking}
          data-testid="breach-check-all-button"
          className="self-start"
        >
          <ScanSearch className="h-4 w-4" />
          {checking ? 'Controllo in corso...' : hasResults ? 'Ricontrolla tutte le password' : 'Controlla violazioni note'}
        </Button>

        {error && <Alert variant="destructive">{error}</Alert>}

        {hasResults && (
          <div className="flex flex-col gap-2">
            {breachedCount > 0 && (
              <Alert variant="destructive">
                Trovate {breachedCount} password compromesse in violazioni note. Cambiale il prima possibile.
              </Alert>
            )}
            {breachedCount === 0 && failedCount === 0 && (
              <Alert variant="success">Nessuna delle tue password risulta in violazioni note.</Alert>
            )}
            {failedCount > 0 && (
              <Alert variant="warning">
                Il controllo non è riuscito per {failedCount}{' '}
                {failedCount === 1 ? 'credenziale' : 'credenziali'} (verifica la connessione e riprova). Questo
                NON significa che la password sia sicura: significa solo che non è stato possibile verificarla.
              </Alert>
            )}

            <div className="flex flex-col gap-2" data-testid="breach-results-list">
              {orderedResults.map((result) => (
                <BreachResultRow
                  key={result.service}
                  result={result}
                  retrying={retryingService === result.service}
                  onRetry={() => handleRetry(result.service)}
                />
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function SecurityDashboard() {
  const [data, setData] = useState<SecurityDashboardData | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .getSecurityDashboard()
      .then(setData)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Errore nel caricamento della dashboard.'))
  }, [])

  if (error) return <Alert variant="destructive">{error}</Alert>
  if (!data) return <p className="text-sm text-muted-foreground">Caricamento...</p>

  return (
    <div className="flex flex-col gap-4" data-testid="security-dashboard">
      <h1 className="text-2xl font-semibold tracking-tight">Dashboard di Sicurezza</h1>
      <Alert variant="info">Questa sezione analizza le tue password per identificare potenziali rischi.</Alert>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric label="Credenziali totali" value={data.total_credentials} icon={KeyRound} tone="primary" />
        <Metric label="Password deboli" value={data.weak_count} icon={ShieldAlert} tone="destructive" />
        <Metric label="Riutilizzate" value={data.reused_count} icon={RefreshCcw} tone="warning" />
        <Metric label="Anziane (>1 anno)" value={data.old_count} icon={Clock3} tone="warning" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <RefreshCcw className="h-4 w-4" /> Password Riutilizzate
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {data.reused_passwords.length === 0 ? (
            <Alert variant="success">Ottimo! Nessuna password riutilizzata trovata.</Alert>
          ) : (
            <>
              <Alert variant="destructive">
                Trovate {data.reused_passwords.length} password riutilizzate. È fondamentale usare una password
                unica per ogni servizio.
              </Alert>
              {data.reused_passwords.map((entry) => (
                <Alert variant="warning" key={entry.services.join(',')}>
                  La password usata per <strong>{entry.services.join(', ')}</strong> è la stessa.
                </Alert>
              ))}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldAlert className="h-4 w-4" /> Password Deboli
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {data.weak_passwords.length === 0 ? (
            <Alert variant="success">Perfetto! Tutte le tue password sono robuste.</Alert>
          ) : (
            <>
              <Alert variant="destructive">
                Trovate {data.weak_passwords.length} password deboli o molto deboli.
              </Alert>
              {data.weak_passwords.map((entry) => (
                <Alert variant="warning" key={entry.service}>
                  La password per <strong>{entry.service}</strong> ha un punteggio di robustezza basso (
                  {entry.score}/4).
                </Alert>
              ))}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="h-4 w-4" /> Password Anziane (più di 1 anno)
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {data.old_passwords.length === 0 ? (
            <Alert variant="success">Tutte le tue password sono state aggiornate di recente.</Alert>
          ) : (
            <>
              <Alert variant="warning">
                Trovate {data.old_passwords.length} password non aggiornate da più di un anno. Considera di
                cambiarle.
              </Alert>
              <ul className="list-inside list-disc text-sm">
                {data.old_passwords.map((service) => (
                  <li key={service}>{service}</li>
                ))}
              </ul>
            </>
          )}
        </CardContent>
      </Card>

      <BreachCheckCard />
    </div>
  )
}
