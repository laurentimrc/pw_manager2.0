import { useState, type FormEvent } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { TagInput } from '@/components/ui/TagInput'
import { PasswordStrengthMeter } from '@/components/credentials/PasswordStrengthMeter'
import { PasswordGeneratorPanel } from '@/components/credentials/PasswordGeneratorPanel'
import { useTags } from '@/hooks/useTags'
import { api, ApiError } from '@/lib/api'

export function AddCredentialForm({ onAdded }: { onAdded: () => void }) {
  const [service, setService] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [totpSecret, setTotpSecret] = useState('')
  const [tags, setTags] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const availableTags = useTags()

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSuccess(null)

    if (!service || !username || !password) {
      setError('I campi Servizio, Username e Password sono obbligatori.')
      return
    }

    setSubmitting(true)
    try {
      await api.addCredential(service, username, password, totpSecret, tags)
      setSuccess(`Credenziale per '${service}' aggiunta!`)
      setService('')
      setUsername('')
      setPassword('')
      setTotpSecret('')
      setTags([])
      onAdded()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il salvataggio.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">Aggiungi Nuova Credenziale</h1>

      <PasswordGeneratorPanel onGenerated={setPassword} />

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Dati Credenziale</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid="add-credential-form">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="add-service">Servizio/Sito Web</Label>
              <Input id="add-service" value={service} onChange={(e) => setService(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="add-username">Username/Email</Label>
              <Input id="add-username" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="add-password">Password</Label>
              <div className="flex gap-2">
                <Input
                  id="add-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  data-testid="add-password-input"
                  className="flex-1"
                />
                <Button
                  type="button"
                  variant="outline"
                  size="icon"
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? 'Nascondi password' : 'Mostra password'}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </Button>
              </div>
              <PasswordStrengthMeter password={password} />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="add-totp">Segreto TOTP (opzionale)</Label>
              <Input
                id="add-totp"
                type="password"
                value={totpSecret}
                onChange={(e) => setTotpSecret(e.target.value)}
                placeholder="Chiave segreta 2FA fornita dal servizio"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="add-tags">Tag</Label>
              <TagInput id="add-tags" tags={tags} onChange={setTags} suggestions={availableTags} />
            </div>
            {error && <Alert variant="destructive">{error}</Alert>}
            {success && <Alert variant="success">{success}</Alert>}
            <Button type="submit" disabled={submitting} data-testid="save-credential-button">
              {submitting ? 'Salvataggio...' : 'Salva Credenziale'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
