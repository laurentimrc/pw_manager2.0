import type { SecurityFlag } from '@/types'

export const FLAG_LABELS: Record<SecurityFlag, string> = {
  weak: 'Debole',
  reused: 'Riutilizzata',
  old: 'Anziana',
}

export const FLAG_BADGE_VARIANT: Record<SecurityFlag, 'destructive' | 'warning' | 'secondary'> = {
  weak: 'destructive',
  reused: 'warning',
  old: 'secondary',
}

export function formatDate(iso: string | null): string {
  if (!iso) return 'Data sconosciuta'
  try {
    return new Date(iso).toLocaleString('it-IT', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return iso
  }
}
