import { useEffect, useState, type FormEvent } from 'react'
import { api, ApiError } from '@/lib/api'
import { Label } from '@/components/ui/Label'
import { Textarea } from '@/components/ui/Textarea'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { TagInput } from '@/components/ui/TagInput'
import { useTags } from '@/hooks/useTags'

export function EditNoteForm({
  noteKey,
  onSaved,
  onCancel,
}: {
  noteKey: string
  onSaved: () => void
  onCancel: () => void
}) {
  const [loading, setLoading] = useState(true)
  const [content, setContent] = useState('')
  const [tags, setTags] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const availableTags = useTags()

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .getNoteSecret(noteKey)
      .then((secret) => {
        if (cancelled) return
        setContent(secret.content)
        setTags(secret.tags)
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : 'Errore nel caricamento della nota.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [noteKey])

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await api.updateNote(noteKey, content, tags)
      onSaved()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante il salvataggio.')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Caricamento nota...</p>
  }

  return (
    <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid={`edit-note-form-${noteKey}`}>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-note-content-${noteKey}`}>Contenuto</Label>
        <Textarea
          id={`edit-note-content-${noteKey}`}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={5}
          data-testid={`edit-note-content-input-${noteKey}`}
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`edit-note-tags-${noteKey}`}>Tag</Label>
        <TagInput id={`edit-note-tags-${noteKey}`} tags={tags} onChange={setTags} suggestions={availableTags} />
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
