import { useRef, useState, type ChangeEvent } from 'react'
import { Upload } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Checkbox'
import { Alert } from '@/components/ui/Alert'
import { api, ApiError } from '@/lib/api'

export function ImportPanel() {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [fileName, setFileName] = useState<string | null>(null)
  const [parsedData, setParsedData] = useState<Record<string, unknown> | null>(null)
  const [entries, setEntries] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [confirmChecked, setConfirmChecked] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    setError(null)
    setSuccess(null)
    setParsedData(null)
    setEntries(null)
    setConfirmChecked(false)
    if (!file) return

    setFileName(file.name)
    let data: Record<string, unknown>
    try {
      data = JSON.parse(await file.text())
    } catch {
      setError('Il file selezionato non è un JSON valido.')
      return
    }

    try {
      // Validazione preliminare via backend (senza salvare nulla): il backend
      // riusa `validate_imported_db` ed espone il numero di voci se i dati sono
      // validi ma non ancora confermati.
      await api.importDb(data, false)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'confirmation_required') {
        setParsedData(data)
        setEntries((err.extra?.entries as number) ?? null)
        return
      }
      setError(err instanceof ApiError ? err.message : 'Errore durante la validazione del file.')
    }
  }

  async function handleImport() {
    if (!parsedData) return
    setSubmitting(true)
    setError(null)
    try {
      const result = await api.importDb(parsedData, true)
      setSuccess(`Database importato: ${result.imported_entries} voci.`)
      setParsedData(null)
      setEntries(null)
      setFileName(null)
      setConfirmChecked(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante l\'importazione.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Importa Database</CardTitle>
        <CardDescription>
          Assicurati che il file importato sia stato criptato con la stessa Master Password.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <input
          ref={fileInputRef}
          type="file"
          accept="application/json"
          onChange={handleFileChange}
          data-testid="import-file-input"
          className="text-sm"
        />

        {error && <Alert variant="destructive">{error}</Alert>}
        {success && <Alert variant="success">{success}</Alert>}

        {entries !== null && (
          <>
            <Alert variant="success">
              File '{fileName}' caricato con {entries} voci.
            </Alert>
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={confirmChecked} onChange={(e) => setConfirmChecked(e.target.checked)} />
              Confermo di voler sostituire l&apos;intero database attuale. L&apos;operazione è irreversibile.
            </label>
            <Button
              type="button"
              variant="destructive"
              disabled={!confirmChecked || submitting}
              onClick={handleImport}
              data-testid="confirm-import-button"
            >
              <Upload className="h-4 w-4" />
              {submitting ? 'Importazione...' : "Sostituisci Database con l'Importazione"}
            </Button>
          </>
        )}
      </CardContent>
    </Card>
  )
}
