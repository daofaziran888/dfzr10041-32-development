/** 登录来源约定与带依据告警的接口封装。 */
import { request } from './client'

export type ConventionSummary = {
  source_id: string
  version: string
  state: string
  active: boolean
}

export type ConventionReport = {
  ok: boolean
  registered?: boolean
  active_version?: string
  errors: { code: string; message: string }[]
  warnings: { code: string; message: string }[]
  missing_evidence: { raw_value: string; normalized: string }[]
  ordinary_conflicts: { raw_value: string; normalized: string }[]
  collisions: Record<string, { raw_value: string; normalized: string; evidence: string }[]>
}

export type LoginEvent = {
  record_id: string
  source_id: string
  line_number: number
  raw_line: string
  field_group: string
  field_values: Record<string, string>
  verdict: string
  review_reason: string
  effective: boolean
  field_version: string
  observations: {
    field: string
    canonical_field: string
    raw_value: string
    normalized: string | null
    field_renamed: boolean
    conversion_evidence?: string
    pending_reason?: string
  }[]
}

export type LoginAlert = {
  alert_id: string
  source_id: string
  threshold: number
  count: number
  triggered: boolean
  convention_version: string
  field_group: string
  delivery_state: string
  confirmed: boolean
  delivered: boolean
  evidence: LoginEvent[]
  excluded: { raw_line: string; reason: string; message: string; verdict: string }[]
  amendments: { correction_id: string; linked_alert_id: string; raw_line: string; delivered: boolean }[]
  interruption: Record<string, unknown>
}

export type HandoverResult = {
  ok: boolean
  decision: string
  can_complete_historical: boolean
  can_complete_new_round: boolean
  can_complete_this_round: boolean
  historical_recompute: { count: number; convention_version: string; rows: LoginEvent[] } | null
  new_round: { count: number; convention_version: string; rows: LoginEvent[] }
  review_checklist: { item: string; raw_line?: string }[]
  excluded_conflicts: { line_number: number; conflict_values: { field: string; raw_value: string }[] }[]
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await request(path, { method: 'POST', body: JSON.stringify(body) })
  if (!response.ok) throw new Error(`接口返回 ${response.status}，操作未生效`)
  return (await response.json()) as T
}

async function getJson<T>(path: string): Promise<T> {
  const response = await request(path)
  if (!response.ok) throw new Error(`接口返回 ${response.status}，数据未更新`)
  return (await response.json()) as T
}

export async function listConventions(): Promise<ConventionSummary[]> {
  const payload = await getJson<{ items: ConventionSummary[] }>('/api/login/conventions')
  return payload.items
}

export async function importConvention(payload: unknown): Promise<ConventionReport> {
  return postJson<ConventionReport>('/api/login/conventions', { payload })
}

export async function classifyEntries(
  sourceId: string,
  entries: { line_number: number; raw_line: string; fields: Record<string, string> }[],
): Promise<LoginEvent[]> {
  const payload = await postJson<{ events: LoginEvent[] }>('/api/login/events/classify', {
    source_id: sourceId,
    entries,
  })
  return payload.events
}

export async function listAlerts(sourceId?: string): Promise<LoginAlert[]> {
  const query = sourceId ? `?source_id=${encodeURIComponent(sourceId)}` : ''
  const payload = await getJson<{ items: LoginAlert[] }>(`/api/login/alerts${query}`)
  return payload.items
}

export async function getAlert(alertId: string): Promise<LoginAlert> {
  return getJson<LoginAlert>(`/api/login/alerts/${alertId}`)
}

export async function checkAlert(sourceId: string, threshold: number): Promise<LoginAlert> {
  return postJson<LoginAlert>('/api/login/alerts/check', { source_id: sourceId, threshold })
}

export async function deliverAlert(
  alertId: string,
  verificationAck: boolean,
): Promise<{ delivery_state: string; interruption: Record<string, unknown> }> {
  return postJson('/api/login/alerts/deliver', {
    alert_id: alertId,
    target: 'alert-receiver',
    target_ack: true,
    verification_ack: verificationAck,
  })
}

export async function resumeAlert(alertId: string): Promise<Record<string, unknown>> {
  return postJson(`/api/login/alerts/${alertId}/resume`, {})
}

export async function confirmAlert(alertId: string): Promise<{ duplicate: boolean }> {
  return postJson(`/api/login/alerts/${alertId}/confirm`, {})
}

export async function handoverAlert(alertId: string): Promise<HandoverResult> {
  return getJson<HandoverResult>(`/api/login/alerts/${alertId}/handover`)
}

export async function correctEvent(
  alertId: string,
  payload: {
    correction_id: string
    source_id: string
    line_number: number
    new_field_values: Record<string, string>
    reason: string
  },
): Promise<{ ok: boolean; duplicate: boolean; amendment: { linked_alert_id: string } }> {
  return postJson('/api/login/corrections', payload)
}
