import { useState } from 'react'
import { ChevronRight, Eye, EyeOff, Pencil, StickyNote, Trash2 } from 'lucide-react'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { TagBadges } from '@/components/ui/TagBadges'
import { CopyButton } from '@/components/credentials/CopyButton'
import { EditNoteForm } from '@/components/notes/EditNoteForm'
import { api, ApiError } from '@/lib/api'
import { formatDate } from '@/lib/flags'
import type { NoteListItem, NoteSecret } from '@/types'

export function NoteItem({
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
  item: NoteListItem
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
  const [showContent, setShowContent] = useState(false)
  const [secret, setSecret] = useState<NoteSecret | null>(null)
  const [secretError, setSecretError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  async function ensureSecretLoaded(): Promise<NoteSecret | null> {
    if (secret) return secret
    try {
      const loaded = await api.getNoteSecret(item.key)
      setSecret(loaded)
      setSecretError(null)
      return loaded
    } catch (err) {
      setSecretError(err instanceof ApiError ? err.message : 'Errore nel recupero della nota.')
      return null
    }
  }

  async function handleToggleShow() {
    if (!showContent) await ensureSecretLoaded()
    setShowContent((prev) => !prev)
  }

  async function handleConfirmDelete() {
    setDeleting(true)
    setDeleteError(null)
    try {
      await api.deleteNote(item.key)
      onDeleted()
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "Errore durante l'eliminazione.")
    } finally {
      setDeleting(false)
    }
  }

  return (
    <Card data-testid={`note-item-${item.key}`}>
      <button
        type="button"
        onClick={() => setExpanded((prev) => !prev)}
        className="flex w-full items-center justify-between gap-3 rounded-2xl p-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        data-testid={`note-toggle-${item.key}`}
      >
        <span className="flex items-center gap-2.5 font-medium">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary">
            <StickyNote className="h-4 w-4" />
          </span>
          {item.key}
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
            <EditNoteForm noteKey={item.key} onSaved={onSaved} onCancel={onCancelEdit} />
          ) : (
            <div className="flex flex-col gap-4">
              <div>
                <p className="text-xs font-medium text-muted-foreground">Contenuto</p>
                <div className="mt-1 flex items-start gap-2">
                  <pre
                    className="glass-1 flex-1 whitespace-pre-wrap break-words rounded-2xl px-3.5 py-2 text-sm font-sans"
                    data-testid={`note-content-${item.key}`}
                  >
                    {showContent ? secret?.content ?? '••••••••••' : '••••••••••'}
                  </pre>
                  <Button type="button" variant="outline" size="sm" onClick={handleToggleShow}>
                    {showContent ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    {showContent ? 'Nascondi' : 'Mostra'}
                  </Button>
                  <CopyButton
                    label="Copia contenuto"
                    getValue={async () => (await ensureSecretLoaded())?.content ?? ''}
                  />
                </div>
                {secretError && <p className="mt-1 text-xs text-destructive">{secretError}</p>}
              </div>

              <p className="text-xs text-muted-foreground">Ultima modifica: {formatDate(item.last_updated)}</p>

              {isPendingDelete ? (
                <div className="flex flex-col gap-2" data-testid={`delete-confirm-note-${item.key}`}>
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
                      data-testid={`confirm-delete-note-${item.key}`}
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
                    data-testid={`delete-button-note-${item.key}`}
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
