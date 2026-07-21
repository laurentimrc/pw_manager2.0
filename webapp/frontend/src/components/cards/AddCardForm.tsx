import { useState, type FormEvent } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { TagInput } from '@/components/ui/TagInput'
import { useTags } from '@/hooks/useTags'
import { api, ApiError } from '@/lib/api'

export function AddCardForm({ onAdded }: { onAdded: () => void }) {
  const [name, setName] = useState('')
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

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    if (!name || !cardNumber) {
      setError('I campi Nome e Numero Carta sono obbligatori.')
      return
    }

    setSubmitting(true)
    try {
      await api.addCard(name, cardholder, cardNumber, expiry, cvv, tags)
      setName('')
      setCardholder('')
      setCardNumber('')
      setExpiry('')
      setCvv('')
      setTags([])
      onAdded()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il salvataggio.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Nuova Carta di Pagamento</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid="add-card-form">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="add-card-name">Nome Carta</Label>
            <Input
              id="add-card-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Es. Visa Personale"
              data-testid="add-card-name-input"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="add-card-holder">Intestatario</Label>
            <Input id="add-card-holder" value={cardholder} onChange={(e) => setCardholder(e.target.value)} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="add-card-number">Numero Carta</Label>
            <div className="flex gap-2">
              <Input
                id="add-card-number"
                type={showCardNumber ? 'text' : 'password'}
                value={cardNumber}
                onChange={(e) => setCardNumber(e.target.value)}
                inputMode="numeric"
                data-testid="add-card-number-input"
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
              <Label htmlFor="add-card-expiry">Scadenza (MM/AA)</Label>
              <Input id="add-card-expiry" value={expiry} onChange={(e) => setExpiry(e.target.value)} placeholder="12/29" />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="add-card-cvv">CVV</Label>
              <div className="flex gap-2">
                <Input
                  id="add-card-cvv"
                  type={showCvv ? 'text' : 'password'}
                  value={cvv}
                  onChange={(e) => setCvv(e.target.value)}
                  inputMode="numeric"
                  data-testid="add-card-cvv-input"
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
            <Label htmlFor="add-card-tags">Tag</Label>
            <TagInput id="add-card-tags" tags={tags} onChange={setTags} suggestions={availableTags} />
          </div>
          {error && <Alert variant="destructive">{error}</Alert>}
          <Button type="submit" disabled={submitting} data-testid="save-card-button">
            {submitting ? 'Salvataggio...' : 'Salva Carta'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
