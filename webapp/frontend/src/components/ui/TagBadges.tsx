import { Badge } from '@/components/ui/Badge'

/** Elenco di tag in sola lettura, usato nell'header di ciascuna voce del
 * vault (login, nota, carta). Non renderizza nulla se la voce non ha tag. */
export function TagBadges({ tags }: { tags: string[] }) {
  if (tags.length === 0) return null
  return (
    <>
      {tags.map((tag) => (
        <Badge key={tag} variant="secondary" data-testid={`tag-badge-${tag}`}>
          {tag}
        </Badge>
      ))}
    </>
  )
}
