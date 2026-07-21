export type SecurityFlag = 'weak' | 'reused' | 'old'

export interface AuthStatus {
  setup_required: boolean
  authenticated: boolean
  lockout_remaining_seconds: number
  session_timeout_seconds: number
}

/** Risposta di setup/login: `recovery_code` è presente (una tantum) solo
 * quando in questa chiamata è stato appena generato un nuovo codice di
 * recovery — al setup iniziale, oppure alla migrazione automatica di un
 * vault "legacy" al primo login riuscito. */
export interface AuthResult {
  authenticated: boolean
  recovery_code?: string | null
}

export interface RecoverCompleteResult {
  recovery_code: string
}

export interface CredentialListItem {
  service: string
  username: string
  last_updated: string | null
  has_totp: boolean
  flags: SecurityFlag[]
  tags: string[]
  decryption_error: boolean
}

export interface CredentialListResponse {
  items: CredentialListItem[]
  total: number
  filtered_total: number
}

export interface CredentialSecret {
  service: string
  username: string
  password: string
  totp_secret: string
  tags: string[]
}

/** Note sicure e carte di pagamento condividono lo stesso concetto di
 * "voce del vault" dei login (stesso file cifrato, stesso spazio di chiavi),
 * ma hanno campi propri: vedi `NoteListItem`/`NoteSecret` e
 * `CardListItem`/`CardSecret`. */
export interface NoteListItem {
  key: string
  tags: string[]
  last_updated: string | null
  decryption_error: boolean
}

export interface NoteListResponse {
  items: NoteListItem[]
  total: number
  filtered_total: number
}

export interface NoteSecret {
  key: string
  content: string
  tags: string[]
  last_updated: string | null
}

export interface CardListItem {
  key: string
  /** Intestatario e scadenza non sono mascherati (solo numero carta e CVV lo
   * sono): compaiono già nell'elenco, come lo username per i login. */
  cardholder: string
  expiry: string
  /** Ultime 4 cifre del numero carta, per riconoscere la carta nell'elenco
   * senza doverla espandere: il numero completo resta mascherato finché non
   * viene esplicitamente richiesto (vedi `CardSecret`). */
  card_number_last4: string
  tags: string[]
  last_updated: string | null
  decryption_error: boolean
}

export interface CardListResponse {
  items: CardListItem[]
  total: number
  filtered_total: number
}

export interface CardSecret {
  key: string
  cardholder: string
  card_number: string
  expiry: string
  cvv: string
  tags: string[]
  last_updated: string | null
}

export interface TagsResponse {
  tags: string[]
}

export interface TotpInfo {
  code: string
  remaining: number
  period: number
}

export interface StrengthResult {
  text: string
  feedback: string
  score: number
  color: string
}

export interface SecurityDashboard {
  total_credentials: number
  weak_count: number
  reused_count: number
  old_count: number
  weak_passwords: { service: string; score: number }[]
  reused_passwords: { services: string[] }[]
  old_passwords: string[]
}

/** Esito del controllo violazioni (HIBP Pwned Passwords) per una singola
 * credenziale. `checked: false` significa che il controllo non è riuscito
 * (rete assente, timeout, API non raggiungibile): è un caso diverso da
 * "nessuna violazione trovata" e va mostrato in modo distinto. */
export interface BreachCheckResult {
  service: string
  breach_count: number | null
  checked: boolean
}

export interface BulkBreachCheckResponse {
  results: BreachCheckResult[]
}

export type SortBy = 'name' | 'recent' | 'weakest'

export interface GeneratorOptions {
  length: number
  use_upper: boolean
  use_lower: boolean
  use_digits: boolean
  use_symbols: boolean
  exclude_ambiguous: boolean
}
