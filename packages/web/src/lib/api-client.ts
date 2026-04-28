// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
//
// Auth model:
//   - access_token / refresh_token live in httpOnly cookies (set by the API).
//     They are never exposed to JavaScript, so an XSS can no longer steal them.
//   - csrf_token is a non-httpOnly cookie. We read it here and echo it back as
//     the X-CSRF-Token header on every state-changing request (double-submit
//     pattern). The API's CSRFMiddleware validates the match.
//   - All requests use credentials: 'include' so the browser attaches the
//     cookies. URLs are relative; in dev Next.js rewrites them to the API,
//     in prod Caddy proxies /api/* on the same domain.

const API_BASE = ''

interface FetchOptions extends RequestInit {}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

// Endpoints that legitimately return 401 as part of their normal flow
// — login on bad password, refresh on a stale refresh-token, etc. We
// MUST NOT treat these as "session expired" or we'll boot the user out
// of /login when they typo their password.
const AUTH_PUBLIC_PATHS = new Set([
  '/api/v1/auth/login',
  '/api/v1/auth/register',
  '/api/v1/auth/refresh',
  '/api/v1/auth/logout',
])

function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null
  const match = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'))
  return match ? decodeURIComponent(match[1]) : null
}

/**
 * Fired by the api client when a request to a protected endpoint comes
 * back 401 AND a one-shot refresh-token attempt also failed. Any layer
 * that cares (auth-store, providers, error overlays) can listen and
 * decide what to do — typically: clear local state and redirect to
 * /login?session=expired. Using a window event keeps the api-client
 * agnostic of the auth-store and the router.
 */
export const SESSION_EXPIRED_EVENT = 'nis2:session-expired'

class ApiClient {
  private baseUrl: string
  // In-flight single-flight refresh promise. Without it, when the page
  // mounts and 5 hooks fire simultaneously they all see 401 and all kick
  // off /auth/refresh. The first refresh rotates the token; the next
  // four hit a now-revoked refresh token and 401 → cascade logout.
  private refreshing: Promise<boolean> | null = null

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }

  private async tryRefresh(): Promise<boolean> {
    if (this.refreshing) return this.refreshing
    this.refreshing = (async () => {
      try {
        const res = await fetch(`${this.baseUrl}/api/v1/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
          // Server reads the refresh token from the httpOnly cookie;
          // body is empty by design, so no Content-Type needed.
        })
        return res.ok
      } catch {
        return false
      } finally {
        // Clear immediately on resolution so the *next* 401 (e.g. 30 min
        // later when the new access token also expires) gets a fresh
        // attempt instead of returning the cached old result.
        this.refreshing = null
      }
    })()
    return this.refreshing
  }

  private async request<T>(path: string, options: FetchOptions = {}, _retry = false): Promise<T> {
    const method = (options.method || 'GET').toUpperCase()
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    }
    if (!SAFE_METHODS.has(method)) {
      const csrf = readCookie('csrf_token')
      if (csrf) headers['X-CSRF-Token'] = csrf
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
      credentials: 'include',
    })

    // 401 on a protected path = access token expired (or wrong cookie
    // on this browser). Try ONE silent refresh, then replay the
    // request. If refresh also 401s, surface a session-expired event
    // and let the auth-store boot the user.
    //
    // We deliberately exclude the public auth paths from this dance —
    // their 401 is the user's password being wrong, not a session
    // problem.
    if (res.status === 401 && !_retry && !AUTH_PUBLIC_PATHS.has(path.split('?')[0])) {
      const refreshed = await this.tryRefresh()
      if (refreshed) {
        return this.request<T>(path, options, true)
      }
      // Refresh failed → genuinely expired. Tell anyone who's listening.
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT))
      }
      throw new Error('Session expired')
    }

    if (res.status === 204) {
      return undefined as T
    }

    if (!res.ok) {
      const error = await res.json().catch(() => ({ detail: res.statusText }))
      const detail = error.detail
      const message = typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || d.message || JSON.stringify(d)).join(', ')
          : `API Error: ${res.status}`
      throw new Error(message)
    }
    return res.json()
  }

  // -------------------------------------------------------------------- Auth
  async register(data: { email: string; password: string; full_name: string; org_name: string }) {
    return this.request<any>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async login(email: string, password: string) {
    return this.request<any>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
  }

  async logout() {
    return this.request<void>('/api/v1/auth/logout', { method: 'POST' })
  }

  async getMe() {
    return this.request<any>('/api/v1/auth/me')
  }

  async updateMe(data: any) {
    return this.request<any>('/api/v1/auth/me', { method: 'PATCH', body: JSON.stringify(data) })
  }

  // ------------------------------------------------------------------- Scans
  async listScans(page = 1, limit = 20) {
    return this.request<any>(`/api/v1/scans?page=${page}&limit=${limit}`)
  }

  async createScan(data: any) {
    return this.request<any>('/api/v1/scans', { method: 'POST', body: JSON.stringify(data) })
  }

  async getScan(id: string) {
    return this.request<any>(`/api/v1/scans/${id}`)
  }

  async getScanResults(scanId: string) {
    return this.request<any>(`/api/v1/scans/${scanId}/results`)
  }

  async getScanFindings(scanId: string) {
    return this.request<any>(`/api/v1/scans/${scanId}/findings`)
  }

  async compareScan(scanId: string, otherId: string) {
    return this.request<any>(`/api/v1/scans/${scanId}/compare/${otherId}`)
  }

  // ---------------------------------------------------------------- Findings
  async listFindings(params: Record<string, string> = {}) {
    const qs = new URLSearchParams(params).toString()
    return this.request<any>(`/api/v1/findings?${qs}`)
  }

  async updateFinding(id: string, data: any) {
    return this.request<any>(`/api/v1/findings/${id}`, { method: 'PATCH', body: JSON.stringify(data) })
  }

  async getFindingStats() {
    return this.request<any>('/api/v1/findings/stats')
  }

  // ------------------------------------------------------------------ Assets
  async listAssets(page = 1) {
    return this.request<any>(`/api/v1/assets?page=${page}`)
  }

  async createAsset(data: any) {
    return this.request<any>('/api/v1/assets', { method: 'POST', body: JSON.stringify(data) })
  }

  async updateAsset(id: string, data: any) {
    return this.request<any>(`/api/v1/assets/${id}`, { method: 'PATCH', body: JSON.stringify(data) })
  }

  async deleteAsset(id: string) {
    return this.request<any>(`/api/v1/assets/${id}`, { method: 'DELETE' })
  }

  // ----------------------------------------------------------- Organizations
  async getOrg(id: string) {
    return this.request<any>(`/api/v1/organizations/${id}`)
  }

  async listOrgs() {
    return this.request<any>('/api/v1/organizations')
  }

  async updateOrg(orgId: string, data: any) {
    return this.request<any>(`/api/v1/organizations/${orgId}`, { method: 'PATCH', body: JSON.stringify(data) })
  }

  async listMembers(orgId: string) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members`)
  }

  async inviteMember(orgId: string, data: { email: string; role: string }) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members`, {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async updateMemberRole(orgId: string, memberId: string, role: string) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members/${memberId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    })
  }

  async removeMember(orgId: string, memberId: string) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members/${memberId}`, {
      method: 'DELETE',
    })
  }

  // ---------------------------------------------------------------- API Keys
  async listApiKeys() {
    return this.request<any>('/api/v1/api-keys')
  }

  async createApiKey(data: { name: string }) {
    return this.request<any>('/api/v1/api-keys', { method: 'POST', body: JSON.stringify(data) })
  }

  async revokeApiKey(id: string) {
    return this.request<any>(`/api/v1/api-keys/${id}`, { method: 'DELETE' })
  }

  // -------------------------------------------------------------- Audit Log
  async listAuditLogs(params: {
    page?: number
    page_size?: number
    action?: string
    resource_type?: string
    user_id?: string
  } = {}) {
    const qs = new URLSearchParams()
    if (params.page) qs.set('page', String(params.page))
    if (params.page_size) qs.set('page_size', String(params.page_size))
    if (params.action) qs.set('action', params.action)
    if (params.resource_type) qs.set('resource_type', params.resource_type)
    if (params.user_id) qs.set('user_id', params.user_id)
    const tail = qs.toString() ? `?${qs.toString()}` : ''
    return this.request<any>(`/api/v1/audit-logs${tail}`)
  }

  // ----------------------------------------------------------------- Reports
  async generateReport(scanId: string, format: string) {
    // The FastAPI endpoint takes scan_id and format as *query parameters*,
    // not body — it has no Pydantic body model. Posting JSON returned 422.
    const qs = new URLSearchParams({ scan_id: scanId, format })
    return this.request<{
      task_id: string
      status: string
      format: string
      scan_id: string
    }>(`/api/v1/reports/generate?${qs.toString()}`, { method: 'POST' })
  }

  async getReportStatus(taskId: string) {
    return this.request<any>(`/api/v1/reports/status/${taskId}`)
  }

  getReportDownloadUrl(taskId: string) {
    return `${this.baseUrl}/api/v1/reports/download/${taskId}`
  }

  // --------------------------------------------------------------- Schedules
  async listSchedules() {
    return this.request<any>('/api/v1/schedules')
  }

  async createSchedule(data: any) {
    return this.request<any>('/api/v1/schedules', { method: 'POST', body: JSON.stringify(data) })
  }

  async updateSchedule(id: string, data: any) {
    return this.request<any>(`/api/v1/schedules/${id}`, { method: 'PATCH', body: JSON.stringify(data) })
  }

  async deleteSchedule(id: string) {
    return this.request<any>(`/api/v1/schedules/${id}`, { method: 'DELETE' })
  }

  async triggerSchedule(id: string) {
    return this.request<any>(`/api/v1/schedules/${id}/run`, { method: 'POST' })
  }
}

export const api = new ApiClient(API_BASE)
