import { useEffect, useState, type FormEvent } from 'react'
import { api, ApiError } from '@/lib/api'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { PasswordStrengthMeter } from '@/components/credentials/PasswordStrengthMeter'

export function EditCredentialForm({
  service,
  onSaved,
  onCancel,
}: {
  service: string
  onSaved: () => void
  onCancel: () => void
}) {
  const [loading, setLoading] = useState(true)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpSecret, setTotpSecret] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .getCredentialSecret(service)
      .then((secret) => {
        if (cancelled) return
        setUsername(secret.username)
        setPassword(secret.password)
        setTotpSecret(secret.totp_secret)
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Errore nel caricamento della credenziale.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [service])

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await api.updateCredential(service, username, password, totpSecret)
      onSaved()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il salvataggio.')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Caricamento credenziale...</p>
  }

  return (
    <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid={`edit-form-${service}`}>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-username-${service}`}>Username/Email</Label>
        <Input id={`edit-username-${service}`} value={username} onChange={(e) => setUsername(e.target.value)} />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-password-${service}`}>Password</Label>
        <Input
          id={`edit-password-${service}`}
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <PasswordStrengthMeter password={password} />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-totp-${service}`}>Segreto TOTP (opzionale)</Label>
        <Input
          id={`edit-totp-${service}`}
          type="password"
          value={totpSecret}
          onChange={(e) => setTotpSecret(e.target.value)}
          placeholder="Lascia vuoto per rimuovere"
        />
      </div>
      {error && <Alert variant="destructive">{error}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" disabled={submitting} className="flex-1">
          {submitting ? 'Salvataggio...' : 'Salva Modifiche'}
        </Button>
        <Button type="button" variant="outline" onClick={onCancel} className="flex-1">
          Annulla
        </Button>
      </div>
    </form>
  )
}
