import { useCallback, useEffect, useState } from 'react'
import { CenteredScreen } from '@/components/layout/CenteredScreen'
import { SetupForm } from '@/components/auth/SetupForm'
import { LoginForm } from '@/components/auth/LoginForm'
import { ForgotPasswordForm } from '@/components/auth/ForgotPasswordForm'
import { AuthenticatedApp } from '@/AuthenticatedApp'
import { Alert } from '@/components/ui/Alert'
import { api, setUnauthorizedHandler, type UnauthorizedReason } from '@/lib/api'
import type { AuthStatus } from '@/types'

type AuthScreen = 'login' | 'forgot-password'

export default function App() {
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [sessionMessage, setSessionMessage] = useState<string | null>(null)
  const [authScreen, setAuthScreen] = useState<AuthScreen>('login')

  const refreshStatus = useCallback(async () => {
    try {
      const result = await api.getAuthStatus()
      setStatus(result)
      setLoadError(null)
      return result
    } catch {
      setLoadError('Impossibile contattare il backend. Verifica che sia in esecuzione su 127.0.0.1:8000.')
      return null
    }
  }, [])

  useEffect(() => {
    refreshStatus().finally(() => setLoading(false))
  }, [refreshStatus])

  useEffect(() => {
    const handler = (reason: UnauthorizedReason) => {
      setSessionMessage(
        reason === 'session_expired'
          ? 'Sessione scaduta per inattività. Effettua nuovamente il login.'
          : 'Devi effettuare il login per continuare.',
      )
      refreshStatus()
    }
    setUnauthorizedHandler(handler)
    return () => setUnauthorizedHandler(null)
  }, [refreshStatus])

  if (loading) {
    return (
      <CenteredScreen>
        <p className="text-center text-sm text-muted-foreground">Caricamento...</p>
      </CenteredScreen>
    )
  }

  if (loadError || !status) {
    return (
      <CenteredScreen>
        <Alert variant="destructive">{loadError ?? 'Errore sconosciuto.'}</Alert>
      </CenteredScreen>
    )
  }

  if (status.setup_required) {
    return (
      <CenteredScreen>
        <SetupForm onDone={refreshStatus} />
      </CenteredScreen>
    )
  }

  if (!status.authenticated) {
    return (
      <CenteredScreen>
        <div className="flex flex-col gap-3">
          {sessionMessage && (
            <Alert variant="warning" data-testid="session-message">
              {sessionMessage}
            </Alert>
          )}
          {authScreen === 'forgot-password' ? (
            <ForgotPasswordForm
              onBackToLogin={() => setAuthScreen('login')}
              onDone={() => {
                setAuthScreen('login')
                setSessionMessage(null)
                refreshStatus()
              }}
            />
          ) : (
            <LoginForm
              initialLockoutSeconds={status.lockout_remaining_seconds}
              onForgotPassword={() => setAuthScreen('forgot-password')}
              onDone={() => {
                setSessionMessage(null)
                refreshStatus()
              }}
            />
          )}
        </div>
      </CenteredScreen>
    )
  }

  return (
    <AuthenticatedApp
      onLogout={() => {
        setSessionMessage(null)
        refreshStatus()
      }}
    />
  )
}
