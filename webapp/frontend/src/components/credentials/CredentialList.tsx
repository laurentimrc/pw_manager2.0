import { useCallback, useEffect, useState } from 'react'
import { Search } from 'lucide-react'
import { Input } from '@/components/ui/Input'
import { Alert } from '@/components/ui/Alert'
import { CredentialItem } from '@/components/credentials/CredentialItem'
import { api, ApiError } from '@/lib/api'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import type { CredentialListResponse, SortBy } from '@/types'

const SORT_OPTIONS: { value: SortBy; label: string }[] = [
  { value: 'name', label: 'Nome (A-Z)' },
  { value: 'recent', label: 'Ultima modifica' },
  { value: 'weakest', label: 'Robustezza (più deboli prima)' },
]

export function CredentialList({ onCountChanged }: { onCountChanged: (total: number) => void }) {
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebouncedValue(search, 250)
  const [sortBy, setSortBy] = useState<SortBy>('name')
  const [data, setData] = useState<CredentialListResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [editingService, setEditingService] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const result = await api.listCredentials(debouncedSearch, sortBy)
      setData(result)
      setError(null)
      onCountChanged(result.total)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore nel caricamento delle credenziali.')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch, sortBy])

  useEffect(() => {
    setPendingDelete(null)
    refresh()
  }, [refresh])

  return (
    <div className="flex flex-col gap-4">
      <h1 className="text-2xl font-semibold">Visualizza, Modifica ed Elimina Credenziali</h1>

      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Cerca per Servizio (es. Google, Amazon...)"
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            data-testid="search-input"
          />
        </div>
        <select
          className="h-10 rounded-xl border border-input bg-background px-3 text-sm shadow-sm transition-[box-shadow] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as SortBy)}
          data-testid="sort-select"
        >
          {SORT_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>

      {error && <Alert variant="destructive">{error}</Alert>}

      {data && (
        <p className="text-sm text-muted-foreground">
          {data.filtered_total} di {data.total} credenziali
        </p>
      )}

      {data && data.filtered_total === 0 && <Alert variant="default">Nessuna credenziale trovata.</Alert>}

      <div className="flex flex-col gap-3">
        {data?.items.map((item) => (
          <CredentialItem
            key={item.service}
            item={item}
            isEditing={editingService === item.service}
            isPendingDelete={pendingDelete === item.service}
            onStartEdit={(service) => {
              setPendingDelete(null)
              setEditingService(service)
            }}
            onCancelEdit={() => setEditingService(null)}
            onSaved={() => {
              setEditingService(null)
              refresh()
            }}
            onRequestDelete={(service) => setPendingDelete(service)}
            onCancelDelete={() => setPendingDelete(null)}
            onDeleted={() => {
              setPendingDelete(null)
              refresh()
            }}
          />
        ))}
      </div>
    </div>
  )
}
