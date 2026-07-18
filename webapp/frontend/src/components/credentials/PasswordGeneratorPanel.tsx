import { useState } from 'react'
import { Wand2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Checkbox'
import { Label } from '@/components/ui/Label'
import { Alert } from '@/components/ui/Alert'
import { api, ApiError } from '@/lib/api'
import type { GeneratorOptions } from '@/types'

export function PasswordGeneratorPanel({ onGenerated }: { onGenerated: (password: string) => void }) {
  const [options, setOptions] = useState<GeneratorOptions>({
    length: 20,
    use_upper: true,
    use_lower: true,
    use_digits: true,
    use_symbols: true,
    exclude_ambiguous: true,
  })
  const [error, setError] = useState<string | null>(null)

  async function handleGenerate() {
    setError(null)
    try {
      const { password } = await api.generatePassword(options)
      onGenerated(password)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Errore nella generazione della password.')
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Wand2 className="h-4 w-4" /> Generatore Password
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="gen-length">Lunghezza: {options.length}</Label>
          <input
            id="gen-length"
            type="range"
            min={8}
            max={128}
            value={options.length}
            onChange={(e) => setOptions((o) => ({ ...o, length: Number(e.target.value) }))}
          />
        </div>

        <div className="grid grid-cols-2 gap-2 text-sm">
          {(
            [
              ['use_upper', 'Maiuscole (A-Z)'],
              ['use_lower', 'Minuscole (a-z)'],
              ['use_digits', 'Numeri (0-9)'],
              ['use_symbols', 'Simboli (@#$%)'],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="flex items-center gap-2">
              <Checkbox
                checked={options[key]}
                onChange={(e) => setOptions((o) => ({ ...o, [key]: e.target.checked }))}
              />
              {label}
            </label>
          ))}
        </div>

        <label className="flex items-center gap-2 text-sm">
          <Checkbox
            checked={options.exclude_ambiguous}
            onChange={(e) => setOptions((o) => ({ ...o, exclude_ambiguous: e.target.checked }))}
          />
          Escludi caratteri ambigui (Il1O0|')
        </label>

        {error && <Alert variant="destructive">{error}</Alert>}

        <Button type="button" onClick={handleGenerate} data-testid="generate-password-button">
          Genera e usa password
        </Button>
      </CardContent>
    </Card>
  )
}
