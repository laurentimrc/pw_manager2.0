import { useState } from 'react'
import { Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { AddCardForm } from '@/components/cards/AddCardForm'
import { CardList } from '@/components/cards/CardList'

export function CardsPage() {
  const [showAddForm, setShowAddForm] = useState(false)
  const [listVersion, setListVersion] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Carte di Pagamento</h1>
        <Button type="button" onClick={() => setShowAddForm((prev) => !prev)} data-testid="toggle-add-card">
          {showAddForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showAddForm ? 'Annulla' : 'Nuova Carta'}
        </Button>
      </div>

      {showAddForm && (
        <AddCardForm
          onAdded={() => {
            setShowAddForm(false)
            setListVersion((v) => v + 1)
          }}
        />
      )}

      <CardList key={listVersion} />
    </div>
  )
}
