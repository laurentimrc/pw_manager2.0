import { useState, type FormEvent } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Label } from '@/components/ui/Label'
import { Textarea } from '@/components/ui/Textarea'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { TagInput } from '@/components/ui/TagInput'
import { useTags } from '@/hooks/useTags'
import { api, ApiError } from '@/lib/api'

export function AddNoteForm({ onAdded }: { onAdded: () => void }) {
  const [title, setTitle] = useState('')
  const [content, setContent] = useState('')
  const [tags, setTags] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const availableTags = useTags()

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)

    if (!title || !content) {
      setError('I campi Titolo e Contenuto sono obbligatori.')
      return
    }

    setSubmitting(true)
    try {
      await api.addNote(title, content, tags)
      setTitle('')
      setContent('')
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
        <CardTitle className="text-base">Nuova Nota Sicura</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-4" onSubmit={handleSubmit} data-testid="add-note-form">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="add-note-title">Titolo</Label>
            <Input
              id="add-note-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              data-testid="add-note-title-input"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="add-note-content">Contenuto</Label>
            <Textarea
              id="add-note-content"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={5}
              data-testid="add-note-content-input"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="add-note-tags">Tag</Label>
            <TagInput id="add-note-tags" tags={tags} onChange={setTags} suggestions={availableTags} />
          </div>
          {error && <Alert variant="destructive">{error}</Alert>}
          <Button type="submit" disabled={submitting} data-testid="save-note-button">
            {submitting ? 'Salvataggio...' : 'Salva Nota'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
