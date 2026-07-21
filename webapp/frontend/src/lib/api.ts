import type {
  AuthResult,
  AuthStatus,
  BreachCheckResult,
  BulkBreachCheckResponse,
  CardListResponse,
  CardSecret,
  CredentialListResponse,
  CredentialSecret,
  GeneratorOptions,
  NoteListResponse,
  NoteSecret,
  RecoverCompleteResult,
  SecurityDashboard,
  SortBy,
  StrengthResult,
  TagsResponse,
  TotpInfo,
} from '@/types'

// Il backend FastAPI ascolta solo su 127.0.0.1. In sviluppo il frontend Vite
// gira sulla stessa interfaccia, su una porta diversa: usiamo `credentials:
// "include"` così il cookie di sessione httpOnly viene inviato/ricevuto anche
// tra origin diversi (stesso "site" ai fini di SameSite=Strict).
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'

export class ApiError extends Error {
  status: number
  code?: string
  extra?: Record<string, unknown>

  constructor(status: number, message: string, code?: string, extra?: Record<string, unknown>) {
    super(message)
    this.status = status
    this.code = code
    this.extra = extra
  }
}

export type UnauthorizedReason = 'not_authenticated' | 'session_expired'
let unauthorizedHandler: ((reason: UnauthorizedReason) => void) | null = null

/** Registra un callback globale invocato quando una richiesta autenticata
 * fallisce per sessione mancante/scaduta, così l'app può riportare l'utente
 * alla schermata di login senza dover propagare il caso manualmente ovunque. */
export function setUnauthorizedHandler(handler: ((reason: UnauthorizedReason) => void) | null) {
  unauthorizedHandler = handler
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    credentials: 'include',
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
  })

  if (!response.ok) {
    let message = `Errore HTTP ${response.status}`
    let code: string | undefined
    let extra: Record<string, unknown> | undefined
    try {
      const body = await response.json()
      const detail = body?.detail
      if (typeof detail === 'string') {
        message = detail
      } else if (detail && typeof detail === 'object') {
        message = detail.message ?? message
        code = detail.code
        extra = detail
      }
    } catch {
      // corpo non-JSON: mantieni il messaggio generico
    }
    if (response.status === 401 && (code === 'not_authenticated' || code === 'session_expired')) {
      unauthorizedHandler?.(code)
    }
    throw new ApiError(response.status, message, code, extra)
  }

  if (response.status === 204) return undefined as T
  return (await response.json()) as T
}

function postJson<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: 'POST', body: JSON.stringify(body) })
}

export const api = {
  getAuthStatus: () => request<AuthStatus>('/api/auth/status'),
  setup: (new_password: string, confirm_password: string) =>
    postJson<AuthResult>('/api/auth/setup', { new_password, confirm_password }),
  login: (password: string) => postJson<AuthResult>('/api/auth/login', { password }),
  logout: () => postJson<{ authenticated: boolean }>('/api/auth/logout', {}),

  verifyRecoveryCode: (recovery_code: string) =>
    postJson<{ valid: boolean }>('/api/auth/recover/verify', { recovery_code }),
  completeRecovery: (recovery_code: string, new_password: string, confirm_password: string) =>
    postJson<RecoverCompleteResult>('/api/auth/recover', { recovery_code, new_password, confirm_password }),

  passwordStrength: (password: string) => postJson<StrengthResult>('/api/password-strength', { password }),
  generatePassword: (options: GeneratorOptions) =>
    postJson<{ password: string }>('/api/password-generator', options),

  listCredentials: (search: string, sortBy: SortBy, tag = '') => {
    const params = new URLSearchParams({ search, sort_by: sortBy, tag })
    return request<CredentialListResponse>(`/api/credentials?${params.toString()}`)
  },
  getCredentialSecret: (service: string) =>
    request<CredentialSecret>(`/api/credentials/${encodeURIComponent(service)}/secret`),
  getCredentialTotp: (service: string) =>
    request<TotpInfo>(`/api/credentials/${encodeURIComponent(service)}/totp`),
  addCredential: (service: string, username: string, password: string, totp_secret: string, tags: string[] = []) =>
    postJson<{ service: string }>('/api/credentials', { service, username, password, totp_secret, tags }),
  updateCredential: (
    service: string,
    username: string,
    password: string,
    totp_secret: string,
    tags: string[] = [],
  ) =>
    request<{ service: string }>(`/api/credentials/${encodeURIComponent(service)}`, {
      method: 'PUT',
      body: JSON.stringify({ username, password, totp_secret, tags }),
    }),
  deleteCredential: (service: string) =>
    request<{ deleted: string }>(`/api/credentials/${encodeURIComponent(service)}`, { method: 'DELETE' }),

  // --- Note sicure ---
  listNotes: (search: string, tag = '') => {
    const params = new URLSearchParams({ search, tag })
    return request<NoteListResponse>(`/api/notes?${params.toString()}`)
  },
  getNoteSecret: (key: string) => request<NoteSecret>(`/api/notes/${encodeURIComponent(key)}/secret`),
  addNote: (title: string, content: string, tags: string[] = []) =>
    postJson<{ key: string }>('/api/notes', { title, content, tags }),
  updateNote: (key: string, content: string, tags: string[] = []) =>
    request<{ key: string }>(`/api/notes/${encodeURIComponent(key)}`, {
      method: 'PUT',
      body: JSON.stringify({ content, tags }),
    }),
  // Il DELETE è generico per chiave (login/nota/carta): riusa lo stesso
  // endpoint di `deleteCredential`, vedi commento nel backend.
  deleteNote: (key: string) => api.deleteCredential(key),

  // --- Carte di pagamento ---
  listCards: (search: string, tag = '') => {
    const params = new URLSearchParams({ search, tag })
    return request<CardListResponse>(`/api/cards?${params.toString()}`)
  },
  getCardSecret: (key: string) => request<CardSecret>(`/api/cards/${encodeURIComponent(key)}/secret`),
  addCard: (
    name: string,
    cardholder: string,
    card_number: string,
    expiry: string,
    cvv: string,
    tags: string[] = [],
  ) => postJson<{ key: string }>('/api/cards', { name, cardholder, card_number, expiry, cvv, tags }),
  updateCard: (
    key: string,
    cardholder: string,
    card_number: string,
    expiry: string,
    cvv: string,
    tags: string[] = [],
  ) =>
    request<{ key: string }>(`/api/cards/${encodeURIComponent(key)}`, {
      method: 'PUT',
      body: JSON.stringify({ cardholder, card_number, expiry, cvv, tags }),
    }),
  deleteCard: (key: string) => api.deleteCredential(key),

  listTags: () => request<TagsResponse>('/api/tags'),

  getSecurityDashboard: () => request<SecurityDashboard>('/api/security/dashboard'),
  checkCredentialBreach: (service: string) =>
    request<BreachCheckResult>(`/api/credentials/${encodeURIComponent(service)}/breach-check`, {
      method: 'POST',
    }),
  checkAllCredentialsBreach: () =>
    request<BulkBreachCheckResponse>('/api/security/breach-check', { method: 'POST' }),

  exportDb: () => request<Record<string, unknown>>('/api/utility/export'),
  importDb: (data: Record<string, unknown>, confirm: boolean) =>
    postJson<{ imported_entries: number }>('/api/utility/import', { data, confirm }),
  changeMasterPassword: (old_password: string, new_password: string, confirm_password: string) =>
    postJson<{ message: string }>('/api/utility/change-master-password', {
      old_password,
      new_password,
      confirm_password,
    }),
  regenerateRecoveryCode: (current_password: string) =>
    postJson<RecoverCompleteResult>('/api/utility/recovery-code', { current_password }),
}
