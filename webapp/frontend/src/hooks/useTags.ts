import { useEffect, useState } from 'react'
import { api } from '@/lib/api'

/** Elenco di tutti i tag distinti già usati nel vault (login + note +
 * carte), per alimentare suggerimenti/autocompletamento e la barra di
 * filtro. `refreshKey` forza un nuovo fetch quando cambia (es. dopo
 * l'aggiunta/modifica di una voce, che può aver introdotto un tag nuovo).
 * Un fallimento del fetch è silenzioso: i tag sono solo un aiuto UX, non
 * bloccano nessun flusso se l'endpoint non è raggiungibile. */
export function useTags(refreshKey?: number): string[] {
  const [tags, setTags] = useState<string[]>([])

  useEffect(() => {
    let cancelled = false
    api
      .listTags()
      .then((result) => {
        if (!cancelled) setTags(result.tags)
      })
      .catch(() => {
        // silenzioso: vedi commento sopra
      })
    return () => {
      cancelled = true
    }
  }, [refreshKey])

  return tags
}
