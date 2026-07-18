import { useState, type FormEvent } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { PasswordStrengthMeter } from '@/components/credentials/PasswordStrengthMeter'
import { RecoveryCodeReveal } from '@/components/auth/RecoveryCodeReveal'
import { api, ApiError } from '@/lib/api'

export function SetupForm({ onDone }: { onDone: () => void }) {
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    if (!newPassword || !confirmPassword) {
      setError('Entrambi i campi sono obbligatori.')
      return
    }
    if (newPassword.length < 12) {
      setError('La Master Password deve essere di almeno 12 caratteri.')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('Le password non coincidono.')
      return
    }

    setSubmitting(true)
    try {
      const result = await api.setup(newPassword, confirmPassword)
      if (result.recovery_code) {
        // La sessione è già attiva (il setup autentica subito), ma non
        // entriamo nell'app finché l'utente non conferma esplicitamente di
        // aver salvato il codice di recovery.
        setRecoveryCode(result.recovery_code)
      } else {
        onDone()
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il setup.')
    } finally {
      setSubmitting(false)
    }
  }

  if (recoveryCode) {
    return (
      <RecoveryCodeReveal
        code={recoveryCode}
        description="La tua Master Password è stata impostata. Questo codice ti permetterà di recuperare l'accesso al vault se in futuro dimenticassi la Master Password."
        onConfirm={onDone}
      />
    )
  }

  return (
    <Card variant="glass" className="animate-spring-in-lg">
      <CardHeader>
        <CardTitle>Imposta la tua Master Password</CardTitle>
        <CardDescription>
          Benvenuto! Crea una password principale robusta per proteggere il tuo database.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="new-password">Nuova Master Password</Label>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="confirm-password">Conferma Master Password</Label>
            <Input
              id="confirm-password"
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
          <PasswordStrengthMeter password={newPassword} />
          {error && <Alert variant="destructive">{error}</Alert>}
          <Button type="submit" disabled={submitting} className="w-full">
            {submitting ? 'Attendere...' : 'Imposta e Accedi'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
