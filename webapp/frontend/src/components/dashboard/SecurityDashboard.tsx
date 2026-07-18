import { useEffect, useState } from 'react'
import { Clock3, KeyRound, RefreshCcw, ShieldAlert, ShieldCheck, type LucideIcon } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Alert } from '@/components/ui/Alert'
import { api, ApiError } from '@/lib/api'
import { cn } from '@/lib/cn'
import type { SecurityDashboard as SecurityDashboardData } from '@/types'

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
    </div>
  )
}
