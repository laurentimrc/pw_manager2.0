import { useState, type KeyboardEvent } from 'react'
import { X } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import { Input } from '@/components/ui/Input'
import { Button } from '@/components/ui/Button'

/** Editor di tag riutilizzabile per login, note e carte: mostra i tag già
 * assegnati come chip rimovibili e permette di aggiungerne di nuovi (Invio,
 * virgola, o il bottone "Aggiungi"). `suggestions` alimenta un datalist HTML
 * nativo con i tag già usati altrove nel vault, per favorire il riuso dello
 * stesso tag invece di crearne varianti leggermente diverse. */
export function TagInput({
  id,
  tags,
  onChange,
  suggestions = [],
}: {
  id?: string
  tags: string[]
  onChange: (tags: string[]) => void
  suggestions?: string[]
}) {
  const [draft, setDraft] = useState('')
  const datalistId = id ? `${id}-suggestions` : undefined

  function commitDraft() {
    const cleaned = draft.trim()
    setDraft('')
    if (cleaned && !tags.includes(cleaned)) {
      onChange([...tags, cleaned])
    }
  }

  function handleKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter' || event.key === ',') {
      event.preventDefault()
      commitDraft()
    } else if (event.key === 'Backspace' && draft === '' && tags.length > 0) {
      onChange(tags.slice(0, -1))
    }
  }

  function removeTag(tag: string) {
    onChange(tags.filter((t) => t !== tag))
  }

  return (
    <div className="flex flex-col gap-2">
      {tags.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {tags.map((tag) => (
            <Badge key={tag} variant="secondary" className="gap-1 pr-1">
              {tag}
              <button
                type="button"
                onClick={() => removeTag(tag)}
                aria-label={`Rimuovi tag ${tag}`}
                data-testid={`remove-tag-${tag}`}
                className="rounded-full p-0.5 transition-colors hover:bg-foreground/10"
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
      <div className="flex gap-2">
        <Input
          id={id}
          list={datalistId}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={commitDraft}
          placeholder="Aggiungi un tag e premi Invio"
          className="flex-1"
          data-testid={id ? `${id}-input` : undefined}
        />
        <Button type="button" variant="outline" onClick={commitDraft}>
          Aggiungi
        </Button>
      </div>
      {datalistId && suggestions.length > 0 && (
        <datalist id={datalistId}>
          {suggestions.map((suggestion) => (
            <option key={suggestion} value={suggestion} />
          ))}
        </datalist>
      )}
    </div>
  )
}
