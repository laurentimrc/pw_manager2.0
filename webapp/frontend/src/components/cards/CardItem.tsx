import { useState } from 'react'
import { ChevronRight, CreditCard, Eye, EyeOff, Pencil, Trash2 } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { TagBadges } from '@/components/ui/TagBadges'
import { CopyButton } from '@/components/credentials/CopyButton'
import { EditCardForm } from '@/components/cards/EditCardForm'
import { api, ApiError } from '@/lib/api'
import { formatDate } from '@/lib/flags'
import type { CardListItem, CardSecret } from '@/types'

export function CardItem({
  item,
  isEditing,
  isPendingDelete,
  onStartEdit,
  onCancelEdit,
  onSaved,
  onRequestDelete,
  onCancelDelete,
  onDeleted,
}: {
  item: CardListItem
  isEditing: boolean
  isPendingDelete: boolean
  onStartEdit: (key: string) => void
  onCancelEdit: () => void
  onSaved: () => void
  onRequestDelete: (key: string) => void
  onCancelDelete: () => void
  onDeleted: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [showCardNumber, setShowCardNumber] = useState(false)
  const [showCvv, setShowCvv] = useState(false)
  const [secret, setSecret] = useState<CardSecret | null>(null)
  const [secretError, setSecretError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  async function ensureSecretLoaded(): Promise<CardSecret | null> {
    if (secret) return secret
    try {
      const loaded = await api.getCardSecret(item.key)
      setSecret(loaded)
      setSecretError(null)
      return loaded
    } catch (err) {
      setSecretError(err instanceof ApiError ? err.message : 'Errore nel recupero della carta.')
      return null
    }
  }

  async function handleToggleCardNumber() {
    if (!showCardNumber) await ensureSecretLoaded()
    setShowCardNumber((prev) => !prev)
  }

  async function handleToggleCvv() {
    if (!showCvv) await ensureSecretLoaded()
    setShowCvv((prev) => !prev)
  }

  async function handleConfirmDelete() {
    setDeleting(true)
    setDeleteError(null)
    try {
      await api.deleteCard(item.key)
      onDeleted()
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "Errore durante l'eliminazione.")
    } finally {
      setDeleting(false)
    }
  }

  const maskedNumber = item.card_number_last4 ? `•••• •••• •••• ${item.card_number_last4}` : '••••••••••'

  return (
    <Card data-testid={`card-item-${item.key}`}>
      <button
        type="button"
        onClick={() => setExpanded((prev) => !prev)}
        className="flex w-full items-center justify-between gap-3 rounded-2xl p-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        data-testid={`card-toggle-${item.key}`}
      >
        <span className="flex items-center gap-2.5 font-medium">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <CreditCard className="h-4 w-4" />
          </span>
          <span className="flex flex-col">
            {item.key}
            <span className="text-xs font-normal tracking-wide text-muted-foreground">{maskedNumber}</span>
          </span>
        </span>
        <span className="flex flex-wrap items-center justify-end gap-2">
          <TagBadges tags={item.tags} />
          <ChevronRight
            className={`h-4 w-4 transition-transform duration-200 ease-[cubic-bezier(0.34,1.56,0.64,1)] ${expanded ? 'rotate-90' : ''}`}
          />
        </span>
      </button>

      {expanded && (
        <div className="animate-spring-in border-t border-border p-4">
          {isEditing ? (
            <EditCardForm cardKey={item.key} onSaved={onSaved} onCancel={onCancelEdit} />
          ) : (
            <div className="flex flex-col gap-4">
              {item.cardholder && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Intestatario</p>
                  <div className="mt-1 flex items-center gap-2">
                    <code className="glass-1 flex-1 rounded-2xl px-3.5 py-2 text-sm">{item.cardholder}</code>
                    <CopyButton label="Copia intestatario" getValue={() => item.cardholder} />
                  </div>
                </div>
              )}

              <div>
                <p className="text-xs font-medium text-muted-foreground">Numero Carta</p>
                <div className="mt-1 flex items-center gap-2">
                  <code
                    className="glass-1 flex-1 rounded-2xl px-3.5 py-2 text-sm tracking-wide"
                    data-testid={`card-number-value-${item.key}`}
                  >
                    {showCardNumber ? secret?.card_number ?? maskedNumber : maskedNumber}
                  </code>
                  <Button type="button" variant="outline" size="sm" onClick={handleToggleCardNumber}>
                    {showCardNumber ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    {showCardNumber ? 'Nascondi' : 'Mostra'}
                  </Button>
                  <CopyButton
                    label="Copia numero carta"
                    getValue={async () => (await ensureSecretLoaded())?.card_number ?? ''}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                {item.expiry && (
                  <div>
                    <p className="text-xs font-medium text-muted-foreground">Scadenza</p>
                    <code className="glass-1 mt-1 block rounded-2xl px-3.5 py-2 text-sm">{item.expiry}</code>
                  </div>
                )}

                <div>
                  <p className="text-xs font-medium text-muted-foreground">CVV</p>
                  <div className="mt-1 flex items-center gap-2">
                    <code
                      className="glass-1 flex-1 rounded-2xl px-3.5 py-2 text-sm tracking-wide"
                      data-testid={`card-cvv-value-${item.key}`}
                    >
                      {showCvv ? secret?.cvv ?? '•••' : '•••'}
                    </code>
                    <Button type="button" variant="outline" size="sm" onClick={handleToggleCvv}>
                      {showCvv ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </Button>
                  </div>
                </div>
              </div>

              {secretError && <p className="text-xs text-destructive">{secretError}</p>}

              <p className="text-xs text-muted-foreground">Ultima modifica: {formatDate(item.last_updated)}</p>

              {isPendingDelete ? (
                <div className="flex flex-col gap-2" data-testid={`delete-confirm-card-${item.key}`}>
                  <Alert variant="warning">
                    Confermi l&apos;eliminazione di <strong>{item.key}</strong>? L&apos;azione è irreversibile.
                  </Alert>
                  {deleteError && <Alert variant="destructive">{deleteError}</Alert>}
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="destructive"
                      className="flex-1"
                      disabled={deleting}
                      onClick={handleConfirmDelete}
                      data-testid={`confirm-delete-card-${item.key}`}
                    >
                      {deleting ? 'Eliminazione...' : 'Conferma eliminazione'}
                    </Button>
                    <Button type="button" variant="outline" className="flex-1" onClick={onCancelDelete}>
                      Annulla
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="flex gap-2">
                  <Button type="button" variant="outline" className="flex-1" onClick={() => onStartEdit(item.key)}>
                    <Pencil className="h-3.5 w-3.5" />
                    Modifica
                  </Button>
                  <Button
                    type="button"
                    variant="destructive"
                    className="flex-1"
                    onClick={() => onRequestDelete(item.key)}
                    data-testid={`delete-button-card-${item.key}`}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Elimina
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
