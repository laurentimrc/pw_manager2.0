import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { Progress } from '@/components/ui/Progress'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import type { StrengthResult } from '@/types'

const COLOR_CLASS: Record<string, string> = {
  red: 'bg-red-500',
  orange: 'bg-orange-500',
  yellow: 'bg-yellow-400',
  green: 'bg-green-500',
  darkgreen: 'bg-emerald-600',
  grey: 'bg-muted-foreground/30',
}

const TEXT_COLOR_CLASS: Record<string, string> = {
  red: 'text-red-600 dark:text-red-400',
  orange: 'text-orange-600 dark:text-orange-400',
  yellow: 'text-yellow-600 dark:text-yellow-400',
  green: 'text-green-600 dark:text-green-400',
  darkgreen: 'text-emerald-700 dark:text-emerald-400',
  grey: 'text-muted-foreground',
}

export function PasswordStrengthMeter({ password }: { password: string }) {
  const debounced = useDebouncedValue(password, 200)
  const [result, setResult] = useState<StrengthResult | null>(null)

  useEffect(() => {
    let cancelled = false
    if (!debounced) {
      setResult(null)
      return
    }
    api
      .passwordStrength(debounced)
      .then((res) => {
        if (!cancelled) setResult(res)
      })
      .catch(() => {
        if (!cancelled) setResult(null)
      })
    return () => {
      cancelled = true
    }
  }, [debounced])

  if (!password) return null

  return (
    <div className="flex flex-col gap-1" data-testid="password-strength-meter">
      <Progress value={((result?.score ?? 0) + 1) * 20} indicatorClassName={COLOR_CLASS[result?.color ?? 'grey']} />
      {result && (
        <p className="text-xs">
          <span className="font-semibold">Robustezza: </span>
          <span className={TEXT_COLOR_CLASS[result.color] ?? ''}>{result.text}</span>
          {result.feedback && <span className="text-muted-foreground italic"> · {result.feedback}</span>}
        </p>
      )}
    </div>
  )
}
