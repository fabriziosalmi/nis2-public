// Copyright (c) 2024-2026 Fabrizio Salmi <fabrizio.salmi@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-only
// NIS2 Compliance Platform — https://github.com/fabriziosalmi/nis2-public
const API_BASE = process.env.NEXT_PUBLIC_API_URL || ''

interface FetchOptions extends RequestInit {
  token?: string
}

class ApiClient {
  private baseUrl: string

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }

  private async request<T>(path: string, options: FetchOptions = {}): Promise<T> {
    const { token, ...fetchOptions } = options
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((fetchOptions.headers as Record<string, string>) || {}),
    }
    if (token) headers['Authorization'] = `Bearer ${token}`

    const res = await fetch(`${this.baseUrl}${path}`, { ...fetchOptions, headers })
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

  // Auth
  async register(data: { email: string; password: string; full_name: string; org_name: string }) {
    return this.request<{ access_token: string; refresh_token: string }>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  async login(email: string, password: string) {
    return this.request<{ access_token: string; refresh_token: string }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
  }

  async getMe(token: string) {
    return this.request<any>('/api/v1/auth/me', { token })
  }

  // Scans
  async listScans(token: string, page = 1, limit = 20) {
    return this.request<any>(`/api/v1/scans?page=${page}&limit=${limit}`, { token })
  }

  async createScan(token: string, data: any) {
    return this.request<any>('/api/v1/scans', { method: 'POST', body: JSON.stringify(data), token })
  }

  async getScan(token: string, id: string) {
    return this.request<any>(`/api/v1/scans/${id}`, { token })
  }

  async getScanResults(token: string, scanId: string) {
    return this.request<any>(`/api/v1/scans/${scanId}/results`, { token })
  }

  async getScanFindings(token: string, scanId: string) {
    return this.request<any>(`/api/v1/scans/${scanId}/findings`, { token })
  }

  // Findings
  async listFindings(token: string, params: Record<string, string> = {}) {
    const qs = new URLSearchParams(params).toString()
    return this.request<any>(`/api/v1/findings?${qs}`, { token })
  }

  async updateFinding(token: string, id: string, data: any) {
    return this.request<any>(`/api/v1/findings/${id}`, { method: 'PATCH', body: JSON.stringify(data), token })
  }

  async getFindingStats(token: string) {
    return this.request<any>('/api/v1/findings/stats', { token })
  }

  // Assets
  async listAssets(token: string, page = 1) {
    return this.request<any>(`/api/v1/assets?page=${page}`, { token })
  }

  async createAsset(token: string, data: any) {
    return this.request<any>('/api/v1/assets', { method: 'POST', body: JSON.stringify(data), token })
  }

  async deleteAsset(token: string, id: string) {
    return this.request<any>(`/api/v1/assets/${id}`, { method: 'DELETE', token })
  }

  // Organizations
  async getOrg(token: string, id: string) {
    return this.request<any>(`/api/v1/organizations/${id}`, { token })
  }

  async listMembers(token: string, orgId: string) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members`, { token })
  }

  async inviteMember(token: string, orgId: string, data: { email: string; role: string }) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members`, {
      method: 'POST',
      body: JSON.stringify(data),
      token,
    })
  }

  async updateMemberRole(token: string, orgId: string, memberId: string, role: string) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members/${memberId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
      token,
    })
  }

  async removeMember(token: string, orgId: string, memberId: string) {
    return this.request<any>(`/api/v1/organizations/${orgId}/members/${memberId}`, {
      method: 'DELETE',
      token,
    })
  }

  // API Keys
  async listApiKeys(token: string) {
    return this.request<any>('/api/v1/api-keys', { token })
  }

  async createApiKey(token: string, data: { name: string }) {
    return this.request<any>('/api/v1/api-keys', { method: 'POST', body: JSON.stringify(data), token })
  }

  async revokeApiKey(token: string, id: string) {
    return this.request<any>(`/api/v1/api-keys/${id}`, { method: 'DELETE', token })
  }
  // Organization settings
  async updateOrg(token: string, orgId: string, data: any) {
    return this.request<any>(`/api/v1/organizations/${orgId}`, { method: 'PATCH', body: JSON.stringify(data), token })
  }

  async listOrgs(token: string) {
    return this.request<any>('/api/v1/organizations', { token })
  }

  // Profile
  async updateMe(token: string, data: any) {
    return this.request<any>('/api/v1/auth/me', { method: 'PATCH', body: JSON.stringify(data), token })
  }

  // Reports
  async generateReport(token: string, scanId: string, format: string) {
    return this.request<any>('/api/v1/reports/generate', {
      method: 'POST',
      body: JSON.stringify({ scan_id: scanId, format }),
      token,
    })
  }

  async getReportStatus(token: string, taskId: string) {
    return this.request<any>(`/api/v1/reports/status/${taskId}`, { token })
  }

  getReportDownloadUrl(taskId: string) {
    return `${this.baseUrl}/api/v1/reports/download/${taskId}`
  }

  // Schedules
  async listSchedules(token: string) {
    return this.request<any>('/api/v1/schedules', { token })
  }

  async createSchedule(token: string, data: any) {
    return this.request<any>('/api/v1/schedules', { method: 'POST', body: JSON.stringify(data), token })
  }

  async updateSchedule(token: string, id: string, data: any) {
    return this.request<any>(`/api/v1/schedules/${id}`, { method: 'PATCH', body: JSON.stringify(data), token })
  }

  async deleteSchedule(token: string, id: string) {
    return this.request<any>(`/api/v1/schedules/${id}`, { method: 'DELETE', token })
  }

  async triggerSchedule(token: string, id: string) {
    return this.request<any>(`/api/v1/schedules/${id}/run`, { method: 'POST', token })
  }

  // Scan comparison
  async compareScan(token: string, scanId: string, otherId: string) {
    return this.request<any>(`/api/v1/scans/${scanId}/compare/${otherId}`, { token })
  }
}

export const api = new ApiClient(API_BASE)
