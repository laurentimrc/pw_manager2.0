import { useEffect, useState, type FormEvent } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { TagInput } from '@/components/ui/TagInput'
import { useTags } from '@/hooks/useTags'

export function EditCardForm({
  cardKey,
  onSaved,
  onCancel,
}: {
  cardKey: string
  onSaved: () => void
  onCancel: () => void
}) {
  const [loading, setLoading] = useState(true)
  const [cardholder, setCardholder] = useState('')
  const [cardNumber, setCardNumber] = useState('')
  const [showCardNumber, setShowCardNumber] = useState(false)
  const [expiry, setExpiry] = useState('')
  const [cvv, setCvv] = useState('')
  const [showCvv, setShowCvv] = useState(false)
  const [tags, setTags] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const availableTags = useTags()

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .getCardSecret(cardKey)
      .then((secret) => {
        if (cancelled) return
        setCardholder(secret.cardholder)
        setCardNumber(secret.card_number)
        setExpiry(secret.expiry)
        setCvv(secret.cvv)
        setTags(secret.tags)
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Errore nel caricamento della carta.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [cardKey])

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await api.updateCard(cardKey, cardholder, cardNumber, expiry, cvv, tags)
      onSaved()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il salvataggio.')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Caricamento carta...</p>
  }

  return (
    <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid={`edit-card-form-${cardKey}`}>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-card-holder-${cardKey}`}>Intestatario</Label>
        <Input id={`edit-card-holder-${cardKey}`} value={cardholder} onChange={(e) => setCardholder(e.target.value)} />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-card-number-${cardKey}`}>Numero Carta</Label>
        <div className="flex gap-2">
          <Input
            id={`edit-card-number-${cardKey}`}
            type={showCardNumber ? 'text' : 'password'}
            value={cardNumber}
            onChange={(e) => setCardNumber(e.target.value)}
            inputMode="numeric"
            className="flex-1"
          />
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={() => setShowCardNumber((prev) => !prev)}
            aria-label={showCardNumber ? 'Nascondi numero carta' : 'Mostra numero carta'}
          >
            {showCardNumber ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`edit-card-expiry-${cardKey}`}>Scadenza (MM/AA)</Label>
          <Input id={`edit-card-expiry-${cardKey}`} value={expiry} onChange={(e) => setExpiry(e.target.value)} />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`edit-card-cvv-${cardKey}`}>CVV</Label>
          <div className="flex gap-2">
            <Input
              id={`edit-card-cvv-${cardKey}`}
              type={showCvv ? 'text' : 'password'}
              value={cvv}
              onChange={(e) => setCvv(e.target.value)}
              inputMode="numeric"
              className="flex-1"
            />
            <Button
              type="button"
              variant="outline"
              size="icon"
              onClick={() => setShowCvv((prev) => !prev)}
              aria-label={showCvv ? 'Nascondi CVV' : 'Mostra CVV'}
            >
              {showCvv ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-card-tags-${cardKey}`}>Tag</Label>
        <TagInput id={`edit-card-tags-${cardKey}`} tags={tags} onChange={setTags} suggestions={availableTags} />
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
