import { useState, type FormEvent } from 'react'
import { KeyRound } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { PasswordStrengthMeter } from '@/components/credentials/PasswordStrengthMeter'
import { api, ApiError } from '@/lib/api'

export function ChangeMasterPasswordPanel() {
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSuccess(null)

    if (!oldPassword || !newPassword || !confirmPassword) {
      setError('Tutti i campi sono obbligatori.')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('Le nuove password non coincidono.')
      return
    }

    setSubmitting(true)
    try {
      const result = await api.changeMasterPassword(oldPassword, newPassword, confirmPassword)
      setSuccess(result.message)
      setOldPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il cambio Master Password.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRound className="h-4 w-4" /> Cambia Master Password
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Alert variant="destructive" className="mb-4">
          ATTENZIONE: Questa operazione è irreversibile. L&apos;intero database verrà ri-criptato.
        </Alert>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid="change-master-password-form">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="old-master-password">Vecchia Master Password</Label>
            <Input
              id="old-master-password"
              type="password"
              value={oldPassword}
              onChange={(e) => setOldPassword(e.target.value)}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="new-master-password">Nuova Master Password</Label>
            <Input
              id="new-master-password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
            <PasswordStrengthMeter password={newPassword} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="confirm-master-password">Conferma Nuova Master Password</Label>
            <Input
              id="confirm-master-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>
          {error && <Alert variant="destructive">{error}</Alert>}
          {success && <Alert variant="success">{success}</Alert>}
          <Button type="submit" variant="destructive" disabled={submitting}>
            {submitting ? 'Attendere...' : 'Cambia Master Password Ora'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
