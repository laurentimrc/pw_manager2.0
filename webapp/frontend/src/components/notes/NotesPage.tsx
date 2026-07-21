import { useState } from 'react'
import { Plus, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { AddNoteForm } from '@/components/notes/AddNoteForm'
import { NoteList } from '@/components/notes/NoteList'

export function NotesPage() {
  const [showAddForm, setShowAddForm] = useState(false)
  const [listVersion, setListVersion] = useState(0)

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Note Sicure</h1>
        <Button type="button" onClick={() => setShowAddForm((prev) => !prev)} data-testid="toggle-add-note">
          {showAddForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showAddForm ? 'Annulla' : 'Nuova Nota'}
        </Button>
      </div>

      {showAddForm && (
        <AddNoteForm
          onAdded={() => {
            setShowAddForm(false)
            setListVersion((v) => v + 1)
          }}
        />
      )}

      <NoteList key={listVersion} />
    </div>
  )
}
