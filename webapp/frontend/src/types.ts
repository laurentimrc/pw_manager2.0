export type SecurityFlag = 'weak' | 'reused' | 'old'

export interface AuthStatus {
  setup_required: boolean
  authenticated: boolean
  lockout_remaining_seconds: number
  session_timeout_seconds: number
}

export interface CredentialListItem {
  service: string
  username: string
  last_updated: string | null
  has_totp: boolean
  flags: SecurityFlag[]
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

export type SortBy = 'name' | 'recent' | 'weakest'

export interface GeneratorOptions {
  length: number
  use_upper: boolean
  use_lower: boolean
  use_digits: boolean
  use_symbols: boolean
  exclude_ambiguous: boolean
}
