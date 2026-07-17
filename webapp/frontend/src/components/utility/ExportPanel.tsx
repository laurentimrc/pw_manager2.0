import { useState } from 'react'
import { Download } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Alert } from '@/components/ui/Alert'
import { api, ApiError } from '@/lib/api'

export function ExportPanel() {
  const [error, setError] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)

  async function handleExport() {
    setError(null)
    setDownloading(true)
    try {
      const data = await api.exportDb()
      if (Object.keys(data).length === 0) {
        setError('Nessun dato da esportare.')
        return
      }
      const blob = new Blob([JSON.stringify(data, null, 4)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'password_backup.json'
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore durante l\'esportazione.')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Esporta Database</CardTitle>
        <CardDescription>Il file scaricato contiene le tue credenziali ancora criptate.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error && <Alert variant="destructive">{error}</Alert>}
        <Button type="button" onClick={handleExport} disabled={downloading} data-testid="export-button">
          <Download className="h-4 w-4" />
          {downloading ? 'Preparazione...' : 'Scarica Backup Criptato (.json)'}
        </Button>
      </CardContent>
    </Card>
  )
}
