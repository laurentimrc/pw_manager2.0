import { useState } from 'react'
import { Sidebar, type View } from '@/components/layout/Sidebar'
import { CredentialList } from '@/components/credentials/CredentialList'
import { AddCredentialForm } from '@/components/credentials/AddCredentialForm'
import { SecurityDashboard } from '@/components/dashboard/SecurityDashboard'
import { UtilityPage } from '@/components/utility/UtilityPage'
import { api } from '@/lib/api'

export function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
  const [view, setView] = useState<View>('list')
  const [credentialCount, setCredentialCount] = useState(0)
  const [listVersion, setListVersion] = useState(0)

  async function handleLock() {
    try {
      await api.logout()
    } finally {
      onLogout()
    }
  }

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar view={view} onChangeView={setView} credentialCount={credentialCount} onLock={handleLock} />
      <main className="flex-1 overflow-y-auto p-6">
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
          {view === 'dashboard' && <SecurityDashboard />}
          {view === 'utility' && <UtilityPage />}
        </div>
      </main>
    </div>
  )
}
