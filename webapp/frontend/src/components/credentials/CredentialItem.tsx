import { useState } from 'react'
import { ChevronRight, Eye, EyeOff, KeyRound, Pencil, Trash2 } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { CopyButton } from '@/components/credentials/CopyButton'
import { TotpDisplay } from '@/components/credentials/TotpDisplay'
import { EditCredentialForm } from '@/components/credentials/EditCredentialForm'
import { api, ApiError } from '@/lib/api'
import { FLAG_BADGE_VARIANT, FLAG_LABELS, formatDate } from '@/lib/flags'
import type { CredentialListItem, CredentialSecret } from '@/types'

export function CredentialItem({
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
  item: CredentialListItem
  isEditing: boolean
  isPendingDelete: boolean
  onStartEdit: (service: string) => void
  onCancelEdit: () => void
  onSaved: () => void
  onRequestDelete: (service: string) => void
  onCancelDelete: () => void
  onDeleted: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [secret, setSecret] = useState<CredentialSecret | null>(null)
  const [secretError, setSecretError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  async function ensureSecretLoaded(): Promise<CredentialSecret | null> {
    if (secret) return secret
    try {
      const loaded = await api.getCredentialSecret(item.service)
      setSecret(loaded)
      setSecretError(null)
      return loaded
    } catch (err) {
      setSecretError(err instanceof ApiError ? err.message : 'Errore nel recupero della password.')
      return null
    }
  }

  async function handleToggleShow() {
    if (!showPassword) await ensureSecretLoaded()
    setShowPassword((prev) => !prev)
  }

  async function handleConfirmDelete() {
    setDeleting(true)
    setDeleteError(null)
    try {
      await api.deleteCredential(item.service)
      onDeleted()
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : 'Errore durante l\'eliminazione.')
    } finally {
      setDeleting(false)
    }
  }

  return (
    <Card data-testid={`credential-item-${item.service}`}>
      <button
        type="button"
        onClick={() => setExpanded((prev) => !prev)}
        className="flex w-full items-center justify-between gap-3 rounded-2xl p-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        data-testid={`credential-toggle-${item.service}`}
      >
        <span className="flex items-center gap-2.5 font-medium">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <KeyRound className="h-4 w-4" />
          </span>
          {item.service}
        </span>
        <span className="flex items-center gap-2">
          {item.flags.map((flag) => (
            <Badge key={flag} variant={FLAG_BADGE_VARIANT[flag]} data-testid={`flag-${flag}-${item.service}`}>
              {FLAG_LABELS[flag]}
            </Badge>
          ))}
          <ChevronRight
            className={`h-4 w-4 transition-transform duration-200 ease-[cubic-bezier(0.34,1.56,0.64,1)] ${expanded ? 'rotate-90' : ''}`}
          />
        </span>
      </button>

      {expanded && (
        <div className="animate-spring-in border-t border-border p-4">
          {isEditing ? (
            <EditCredentialForm service={item.service} onSaved={onSaved} onCancel={onCancelEdit} />
          ) : (
            <div className="flex flex-col gap-4">
              <div>
                <p className="text-xs font-medium text-muted-foreground">Username/Email</p>
                <div className="mt-1 flex items-center gap-2">
                  <code className="glass-1 flex-1 rounded-2xl px-3.5 py-2 text-sm">{item.username}</code>
                  <CopyButton label="Copia username" getValue={() => item.username} />
                </div>
              </div>

              <div>
                <p className="text-xs font-medium text-muted-foreground">Password</p>
                <div className="mt-1 flex items-center gap-2">
                  <code
                    className="glass-1 flex-1 rounded-2xl px-3.5 py-2 text-sm tracking-wide"
                    data-testid={`password-value-${item.service}`}
                  >
                    {showPassword ? secret?.password ?? '••••••••••' : '••••••••••'}
                  </code>
                  <Button type="button" variant="outline" size="sm" onClick={handleToggleShow}>
                    {showPassword ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    {showPassword ? 'Nascondi' : 'Mostra'}
                  </Button>
                  <CopyButton
                    label="Copia password"
                    getValue={async () => (await ensureSecretLoaded())?.password ?? ''}
                  />
                </div>
                {secretError && <p className="mt-1 text-xs text-destructive">{secretError}</p>}
              </div>

              {item.has_totp && <TotpDisplay service={item.service} />}

              <p className="text-xs text-muted-foreground">Ultima modifica: {formatDate(item.last_updated)}</p>

              {isPendingDelete ? (
                <div className="flex flex-col gap-2" data-testid={`delete-confirm-${item.service}`}>
                  <Alert variant="warning">
                    Confermi l&apos;eliminazione di <strong>{item.service}</strong>? L&apos;azione è irreversibile.
                  </Alert>
                  {deleteError && <Alert variant="destructive">{deleteError}</Alert>}
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="destructive"
                      className="flex-1"
                      disabled={deleting}
                      onClick={handleConfirmDelete}
                      data-testid={`confirm-delete-${item.service}`}
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
                  <Button type="button" variant="outline" className="flex-1" onClick={() => onStartEdit(item.service)}>
                    <Pencil className="h-3.5 w-3.5" />
                    Modifica
                  </Button>
                  <Button
                    type="button"
                    variant="destructive"
                    className="flex-1"
                    onClick={() => onRequestDelete(item.service)}
                    data-testid={`delete-button-${item.service}`}
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
