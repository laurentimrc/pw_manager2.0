import { useRef, useState } from 'react'
import { Sidebar, type View } from '@/components/layout/Sidebar'
import { CredentialList } from '@/components/credentials/CredentialList'
import { AddCredentialForm } from '@/components/credentials/AddCredentialForm'
import { NotesPage } from '@/components/notes/NotesPage'
import { CardsPage } from '@/components/cards/CardsPage'
import { SecurityDashboard } from '@/components/dashboard/SecurityDashboard'
import { UtilityPage } from '@/components/utility/UtilityPage'
import { useParallaxWash } from '@/hooks/useParallaxWash'
import { api } from '@/lib/api'

export function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
  const [view, setView] = useState<View>('list')
  const [credentialCount, setCredentialCount] = useState(0)
  const [listVersion, setListVersion] = useState(0)
  const shellRef = useRef<HTMLDivElement>(null)
  useParallaxWash(shellRef)

  async function handleLock() {
    try {
      await api.logout()
    } finally {
      onLogout()
    }
  }

  return (
    <div ref={shellRef} className="app-shell flex min-h-screen gap-4 p-4">
      <Sidebar view={view} onChangeView={setView} credentialCount={credentialCount} onLock={handleLock} />
      <main className="relative z-[1] flex-1 overflow-y-auto py-1">
        <div className="mx-auto max-w-3xl">
          {view === 'list' && <CredentialList key={listVersion} onCountChanged={setCredentialCount} />}
          {view === 'add' && (
            <AddCredentialForm
              onAdded={() => {
                setListVersion((v) => v + 1)
                setView('list')
              }}
            />
          )}
          {view === 'notes' && <NotesPage />}
          {view === 'cards' && <CardsPage />}
          {view === 'dashboard' && <SecurityDashboard />}
          {view === 'utility' && <UtilityPage />}
        </div>
      </main>
    </div>
  )
}
