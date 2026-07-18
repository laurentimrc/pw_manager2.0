import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { Checkbox } from '@/components/ui/Checkbox'

/**
 * Mostra un codice di recovery UNA SOLA VOLTA, con conferma esplicita
 * dell'utente prima di poter proseguire (stesso pattern dei backup code 2FA:
 * il codice non sarà più recuperabile una volta chiuso questo schermo, dato
 * che il backend non lo salva mai in chiaro).
 */
export function RecoveryCodeReveal({
  code,
  description,
  onConfirm,
}: {
  code: string
  description: string
  onConfirm: () => void
}) {
  const [confirmed, setConfirmed] = useState(false)

  return (
    <Card variant="glass" className="animate-spring-in-lg">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-amber-500" />
          Salva il tuo codice di recovery
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <Alert variant="warning">
          Questo codice viene mostrato UNA SOLA VOLTA e non potrà essere recuperato in seguito. Se lo perdi e
          dimentichi anche la Master Password, non potrai più accedere alle tue credenziali salvate.
        </Alert>
        <div
          className="select-all rounded-2xl border border-border bg-muted px-4 py-4 text-center font-mono text-lg font-semibold tracking-wider"
          data-testid="recovery-code-value"
        >
          {code}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <Checkbox
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            data-testid="recovery-code-confirm-checkbox"
          />
          Ho salvato il codice di recovery in un posto sicuro.
        </label>
        <Button
          type="button"
          disabled={!confirmed}
          onClick={onConfirm}
          className="w-full"
          data-testid="recovery-code-continue"
        >
          Continua
        </Button>
      </CardContent>
    </Card>
  )
}
