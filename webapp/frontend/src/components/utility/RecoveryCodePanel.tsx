import { useState, type FormEvent } from 'react'
import { ShieldCheck } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { RecoveryCodeReveal } from '@/components/auth/RecoveryCodeReveal'
import { api, ApiError } from '@/lib/api'

/**
 * Permette di generare un nuovo codice di recovery in qualunque momento da
 * autenticati, non solo al primo setup: chiude il gap per cui il codice
 * generato alla migrazione automatica di un vault legacy poteva andare
 * perso se quel momento capitava nell'interfaccia Streamlit (che non ha una
 * UI di recovery). Richiede la master password corrente come conferma
 * esplicita, invalida il codice precedente.
 */
export function RecoveryCodePanel() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [newCode, setNewCode] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    if (!currentPassword) {
      setError('La Master Password corrente è obbligatoria.')
      return
    }
    setSubmitting(true)
    try {
      const result = await api.regenerateRecoveryCode(currentPassword)
      setNewCode(result.recovery_code)
      setCurrentPassword('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante la generazione del codice.')
    } finally {
      setSubmitting(false)
    }
  }

  if (newCode) {
    return (
      <RecoveryCodeReveal
        code={newCode}
        description="Il nuovo codice di recovery è pronto. Il codice precedente non è più valido."
        onConfirm={() => setNewCode(null)}
      />
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheck className="h-4 w-4" /> Codice di Recovery
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Alert variant="warning" className="mb-4">
          Genera un nuovo codice di recovery in qualsiasi momento, ad esempio se hai perso quello attuale. Il codice
          precedente smette immediatamente di funzionare.
        </Alert>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid="regenerate-recovery-code-form">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="recovery-current-password">Master Password corrente</Label>
            <Input
              id="recovery-current-password"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>
          {error && <Alert variant="destructive">{error}</Alert>}
          <Button type="submit" disabled={submitting}>
            {submitting ? 'Attendere...' : 'Genera nuovo codice di recovery'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
