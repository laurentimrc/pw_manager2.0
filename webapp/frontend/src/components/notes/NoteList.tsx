import { useCallback, useEffect, useState } from 'react'
import { Search } from 'lucide-react'
import { Input } from '@/components/ui/Input'
import { Alert } from '@/components/ui/Alert'
import { TagFilterBar } from '@/components/ui/TagFilterBar'
import { NoteItem } from '@/components/notes/NoteItem'
import { api, ApiError } from '@/lib/api'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useTags } from '@/hooks/useTags'
import type { NoteListResponse } from '@/types'

export function NoteList() {
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebouncedValue(search, 250)
  const [tag, setTag] = useState('')
  const [data, setData] = useState<NoteListResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editingKey, setEditingKey] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<string | null>(null)
  const [tagsRefresh, setTagsRefresh] = useState(0)
  const availableTags = useTags(tagsRefresh)

  const refresh = useCallback(async () => {
    try {
      const result = await api.listNotes(debouncedSearch, tag)
      setData(result)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore nel caricamento delle note.')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch, tag])

  useEffect(() => {
    setPendingDelete(null)
    refresh()
  }, [refresh])

  return (
    <div className="flex flex-col gap-4">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          placeholder="Cerca per titolo..."
          className="pl-9"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          data-testid="note-search-input"
        />
      </div>

      <TagFilterBar tags={availableTags} selected={tag} onSelect={setTag} />

      {error && <Alert variant="destructive">{error}</Alert>}

      {data && (
        <p className="text-sm text-muted-foreground">
          {data.filtered_total} di {data.total} note
        </p>
      )}

      {data && data.filtered_total === 0 && <Alert variant="default">Nessuna nota trovata.</Alert>}

      <div className="flex flex-col gap-3">
        {data?.items.map((item) => (
          <NoteItem
            key={item.key}
            item={item}
            isEditing={editingKey === item.key}
            isPendingDelete={pendingDelete === item.key}
            onStartEdit={(key) => {
              setPendingDelete(null)
              setEditingKey(key)
            }}
            onCancelEdit={() => setEditingKey(null)}
            onSaved={() => {
              setEditingKey(null)
              refresh()
              setTagsRefresh((v) => v + 1)
            }}
            onRequestDelete={(key) => setPendingDelete(key)}
            onCancelDelete={() => setPendingDelete(null)}
            onDeleted={() => {
              setPendingDelete(null)
              refresh()
              setTagsRefresh((v) => v + 1)
            }}
          />
        ))}
      </div>
    </div>
  )
}
