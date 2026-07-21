import { Badge } from '@/components/ui/Badge'
import { cn } from '@/lib/cn'

/** Barra di filtro per tag: una fila di chip cliccabili, una sola selezione
 * attiva alla volta (coerente col parametro `tag` singolo accettato dagli
 * endpoint di elenco lato backend). Non renderizza nulla se non esistono
 * ancora tag nel vault, per non occupare spazio inutilmente. */
export function TagFilterBar({
  tags,
  selected,
  onSelect,
}: {
  tags: string[]
  selected: string
  onSelect: (tag: string) => void
}) {
  if (tags.length === 0) return null

  return (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="tag-filter-bar">
      <button type="button" onClick={() => onSelect('')} className="rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background">
        <Badge
          variant={selected === '' ? 'default' : 'outline'}
          className={cn('cursor-pointer select-none', selected === '' && 'ring-1 ring-primary/40')}
        >
          Tutti i tag
        </Badge>
      </button>
      {tags.map((tag) => (
        <button
          key={tag}
          type="button"
          onClick={() => onSelect(selected === tag ? '' : tag)}
          data-testid={`tag-filter-${tag}`}
          className="rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1 focus-visible:ring-offset-background"
        >
          <Badge
            variant={selected === tag ? 'default' : 'outline'}
            className={cn('cursor-pointer select-none', selected === tag && 'ring-1 ring-primary/40')}
          >
            {tag}
          </Badge>
        </button>
      ))}
    </div>
  )
}
