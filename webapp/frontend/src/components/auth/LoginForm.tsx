import { useEffect, useState, type FormEvent } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { RecoveryCodeReveal } from '@/components/auth/RecoveryCodeReveal'
import { api, ApiError } from '@/lib/api'

export function LoginForm({
  initialLockoutSeconds,
  onDone,
  onForgotPassword,
}: {
  initialLockoutSeconds: number
  onDone: () => void
  onForgotPassword: () => void
}) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [lockoutRemaining, setLockoutRemaining] = useState(initialLockoutSeconds)
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null)

  useEffect(() => {
    if (lockoutRemaining <= 0) return
    const timer = setInterval(() => {
      setLockoutRemaining((prev) => Math.max(0, prev - 1))
    }, 1000)
    return () => clearInterval(timer)
  }, [lockoutRemaining])

  const locked = lockoutRemaining > 0

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    if (locked) return

    setSubmitting(true)
    try {
      const result = await api.login(password)
      if (result.recovery_code) {
        // Capita solo quando questo login ha appena migrato un vault
        // "legacy" (creato prima dell'introduzione della DEK/recovery): il
        // primo codice di recovery va mostrato una sola volta, esattamente
        // come al setup.
        setRecoveryCode(result.recovery_code)
      } else {
        onDone()
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
        const remaining = (err.extra?.remaining_seconds as number | undefined) ?? 0
        if (err.status === 423 && remaining > 0) {
          setLockoutRemaining(remaining)
        }
      } else {
        setError('Errore durante il login.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  if (recoveryCode) {
    return (
      <RecoveryCodeReveal
        code={recoveryCode}
        description="Questo vault è stato appena aggiornato a un formato più sicuro: ecco il tuo primo codice di recovery."
        onConfirm={onDone}
      />
    )
  }

  return (
    <Card variant="glass" className="animate-spring-in-lg">
      <CardHeader>
        <CardTitle>Login</CardTitle>
      </CardHeader>
      <CardContent>
        {locked ? (
          <Alert variant="destructive" data-testid="lockout-alert">
            Troppi tentativi falliti. Riprova tra {lockoutRemaining} secondi.
          </Alert>
        ) : (
          <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="master-password">Inserisci la Master Password</Label>
              <Input
                id="master-password"
                type="password"
                autoComplete="current-password"
                autoFocus
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {error && <Alert variant="destructive">{error}</Alert>}
            <Button type="submit" disabled={submitting} className="w-full">
              {submitting ? 'Attendere...' : 'Sblocca'}
            </Button>
            <Button
              type="button"
              variant="link"
              className="self-center text-xs"
              onClick={onForgotPassword}
              data-testid="forgot-password-link"
            >
              Hai dimenticato la Master Password?
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  )
}
