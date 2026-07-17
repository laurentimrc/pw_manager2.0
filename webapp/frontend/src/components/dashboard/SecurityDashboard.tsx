import { useEffect, useState } from 'react'
import { AlertTriangle, RefreshCcw, ShieldAlert, ShieldCheck } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Alert } from '@/components/ui/Alert'
import { api, ApiError } from '@/lib/api'
import type { SecurityDashboard as SecurityDashboardData } from '@/types'

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <Card className="flex flex-col gap-1 p-4">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className="text-2xl font-semibold">{value}</span>
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
      <h1 className="text-2xl font-semibold">Dashboard di Sicurezza</h1>
      <Alert variant="info">Questa sezione analizza le tue password per identificare potenziali rischi.</Alert>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Metric label="Credenziali totali" value={data.total_credentials} />
        <Metric label="Password deboli" value={data.weak_count} />
        <Metric label="Riutilizzate" value={data.reused_count} />
        <Metric label="Anziane (>1 anno)" value={data.old_count} />
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
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
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
