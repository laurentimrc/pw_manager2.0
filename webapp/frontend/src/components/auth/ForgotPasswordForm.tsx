import { useState, type FormEvent } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { PasswordStrengthMeter } from '@/components/credentials/PasswordStrengthMeter'
import { RecoveryCodeReveal } from '@/components/auth/RecoveryCodeReveal'
import { api, ApiError } from '@/lib/api'

type Step = 'code' | 'new-password' | 'reveal'

/**
 * Flusso "Hai dimenticato la Master Password?": tre passi.
 * 1) l'utente inserisce il codice di recovery salvato al momento del setup
 *    (verificato subito, per un errore chiaro senza dover anche compilare la
 *    nuova password);
 * 2) imposta una nuova Master Password (obbligatoria: quella vecchia è
 *    dimenticata);
 * 3) il vecchio codice viene invalidato e un NUOVO codice di recovery viene
 *    mostrato una sola volta, con la stessa conferma esplicita del setup.
 * Nessuna sessione viene creata da questo flusso: al termine l'utente torna
 * alla schermata di login e accede con la nuova Master Password.
 */
export function ForgotPasswordForm({
  onDone,
  onBackToLogin,
}: {
  onDone: () => void
  onBackToLogin: () => void
}) {
  const [step, setStep] = useState<Step>('code')
  const [code, setCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [newRecoveryCode, setNewRecoveryCode] = useState<string | null>(null)

  async function handleVerifyCode(event: FormEvent) {
    event.preventDefault()
    setError(null)
    if (!code.trim()) {
      setError('Inserisci il codice di recovery.')
      return
    }
    setSubmitting(true)
    try {
      await api.verifyRecoveryCode(code)
      setStep('new-password')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Codice di recovery non valido.')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleSetNewPassword(event: FormEvent) {
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
      const result = await api.completeRecovery(code, newPassword, confirmPassword)
      setNewRecoveryCode(result.recovery_code)
      setStep('reveal')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il recovery.')
    } finally {
      setSubmitting(false)
    }
  }

  if (step === 'reveal' && newRecoveryCode) {
    return (
      <RecoveryCodeReveal
        code={newRecoveryCode}
        description="La Master Password è stata reimpostata. Il codice di recovery precedente non è più valido: ecco il nuovo codice."
        onConfirm={onDone}
      />
    )
  }

  return (
    <Card variant="glass" className="animate-spring-in-lg">
      <CardHeader>
        <CardTitle>Recupera l&apos;accesso</CardTitle>
        <CardDescription>
          {step === 'code'
            ? 'Inserisci il codice di recovery che hai salvato al momento del setup.'
            : 'Codice verificato. Imposta una nuova Master Password: quella precedente non è più utilizzabile.'}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {step === 'code' ? (
          <form className="flex flex-col gap-4" onSubmit={handleVerifyCode} data-testid="recovery-code-form">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="recovery-code">Codice di recovery</Label>
              <Input
                id="recovery-code"
                autoFocus
                autoComplete="off"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="XXXX-XXXX-XXXX-XXXX-XXXX"
              />
            </div>
            {error && <Alert variant="destructive">{error}</Alert>}
            <Button type="submit" disabled={submitting} className="w-full">
              {submitting ? 'Verifica...' : 'Verifica codice'}
            </Button>
            <Button type="button" variant="ghost" onClick={onBackToLogin} className="w-full">
              Torna al login
            </Button>
          </form>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={handleSetNewPassword}
            data-testid="recovery-new-password-form"
          >
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="recovery-new-password">Nuova Master Password</Label>
              <Input
                id="recovery-new-password"
                type="password"
                autoComplete="new-password"
                autoFocus
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="recovery-confirm-password">Conferma Nuova Master Password</Label>
              <Input
                id="recovery-confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
            <PasswordStrengthMeter password={newPassword} />
            {error && <Alert variant="destructive">{error}</Alert>}
            <Button type="submit" disabled={submitting} className="w-full">
              {submitting ? 'Attendere...' : 'Reimposta Master Password'}
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  )
}
