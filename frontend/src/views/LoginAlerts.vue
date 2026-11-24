<template>
  <section class="page">
    <header class="page-head">
      <div>
        <h2>登录告警依据</h2>
        <p class="page-desc">
          按来源约定核对登录动作换名与取值转换；登录告警只计实际有效候选，
          每条都能回查字段组与原始日志行。
        </p>
      </div>
      <div class="page-actions">
        <input v-model="sourceId" data-testid="login-source" placeholder="来源编号，如 SRC-JIA" />
        <input v-model.number="threshold" data-testid="login-threshold" type="number" min="0" />
        <button class="btn primary" data-testid="login-check" type="button" @click="runCheck">计算告警</button>
      </div>
    </header>

    <p v-if="errorMessage" class="error-text">{{ errorMessage }}</p>

    <div class="stat-row">
      <article class="stat-card">
        <span class="stat-label">有效登录候选</span>
        <strong class="stat-value">{{ alert?.count ?? '—' }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">告警门槛</span>
        <strong class="stat-value">{{ alert?.threshold ?? threshold }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">告警状态</span>
        <strong class="stat-value">{{ alert ? (alert.triggered ? '已触发' : '未触发') : '—' }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">交付状态</span>
        <strong class="stat-value">{{ alert?.delivery_state ?? '—' }}</strong>
      </article>
    </div>

    <template v-if="alert">
      <h3 class="section-title">实际参与告警的原行（字段版本 {{ alert.convention_version }} / 字段组 {{ alert.field_group }}）</h3>
      <table class="data-table" data-testid="login-evidence-table">
        <thead>
          <tr><th>行号</th><th>原行</th><th>字段取值</th><th>转换依据</th><th>动作</th></tr>
        </thead>
        <tbody>
          <tr v-for="row in alert.evidence" :key="row.record_id">
            <td>{{ row.line_number }}</td>
            <td class="mono">{{ row.raw_line }}</td>
            <td>{{ fieldSummary(row) }}</td>
            <td>{{ evidenceSummary(row) }}</td>
            <td><button class="link" type="button" @click="openCorrection(row)">更正这条</button></td>
          </tr>
          <tr v-if="!alert.evidence.length"><td colspan="5" class="empty-state">没有有效登录候选</td></tr>
        </tbody>
      </table>

      <h3 class="section-title">未计入的原行及原因</h3>
      <table class="data-table" data-testid="login-excluded-table">
        <thead><tr><th>原行</th><th>判定</th><th>原因</th></tr></thead>
        <tbody>
          <tr v-for="(row, index) in alert.excluded" :key="`${row.raw_line}-${index}`">
            <td class="mono">{{ row.raw_line || '—' }}</td>
            <td>{{ row.verdict || '—' }}</td>
            <td>{{ row.message }}</td>
          </tr>
          <tr v-if="!alert.excluded.length"><td colspan="3" class="empty-state">没有排除项</td></tr>
        </tbody>
      </table>

      <h3 class="section-title">交付与交班</h3>
      <div class="filter-bar">
        <button class="btn" type="button" @click="runDeliver(true)">告警目标+字段核验端都确认</button>
        <button class="btn" type="button" @click="runDeliver(false)">仅告警目标确认（模拟核验未达）</button>
        <button class="btn" type="button" @click="runResume">中断后恢复</button>
        <button class="btn" type="button" @click="runConfirm">交班确认</button>
        <button class="btn" type="button" @click="runHandover">本轮能否完成</button>
      </div>
      <p v-if="notice" class="notice-text" data-testid="login-notice">{{ notice }}</p>
      <p v-if="alert.interruption && alert.interruption.reason" class="error-text">
        交付中断：{{ alert.interruption.reason }}（原告警已送达，恢复后不重新计数）
      </p>

      <h3 class="section-title">已关联的修正依据</h3>
      <table class="data-table" data-testid="login-amendment-table">
        <thead><tr><th>更正编号</th><th>关联合告警</th><th>原行</th><th>交付</th></tr></thead>
        <tbody>
          <tr v-for="row in alert.amendments" :key="row.correction_id">
            <td>{{ row.correction_id }}</td>
            <td>{{ row.linked_alert_id }}</td>
            <td class="mono">{{ row.raw_line }}</td>
            <td>{{ row.delivered ? '已交付' : '待交付' }}</td>
          </tr>
          <tr v-if="!alert.amendments.length"><td colspan="4" class="empty-state">暂无修正</td></tr>
        </tbody>
      </table>

      <div v-if="handover" class="handover-box" data-testid="login-handover">
        <h3 class="section-title">交班判定</h3>
        <p>{{ handover.decision }}</p>
        <ul>
          <li>历史口径重算：{{ handover.historical_recompute?.count ?? '不可用' }} 条（{{ handover.historical_recompute?.convention_version || '无已确认口径' }}）</li>
          <li>下一轮按新约定真实计数：{{ handover.new_round.count }} 条（{{ handover.new_round.convention_version || '无约定' }}）</li>
          <li>矛盾原值：{{ handover.excluded_conflicts.length }} 条</li>
        </ul>
        <p class="page-desc">复核清单：{{ handover.review_checklist.map((item) => item.item).join('、') || '无' }}</p>
      </div>
    </template>

    <div v-if="correction" class="modal-backdrop" data-testid="login-correction-modal">
      <form class="modal" @submit.prevent="submitCorrection">
        <h3>更正原行动作</h3>
        <p class="page-desc">原行：{{ correction.raw_line }}</p>
        <label v-for="obs in correction.observations" :key="obs.field" class="create-field">
          <span>{{ obs.field }}（原值 {{ obs.raw_value }}）</span>
          <input v-model="correctionValues[obs.field]" :data-testid="`login-correct-${obs.field}`" />
        </label>
        <label class="create-field">
          <span>更正说明</span>
          <input v-model="correctionReason" data-testid="login-correct-reason" />
        </label>
        <div class="page-actions">
          <button class="btn" type="button" @click="correction = null">取消</button>
          <button class="btn primary" type="submit">提交更正</button>
        </div>
      </form>
    </div>
  </section>
</template>

<script setup lang="ts">
import { ref } from 'vue'

import {
  checkAlert,
  confirmAlert,
  correctEvent,
  deliverAlert,
  getAlert,
  handoverAlert,
  resumeAlert,
} from '@/api/login'
import type { HandoverResult, LoginAlert, LoginEvent } from '@/api/login'

const sourceId = ref('SRC-JIA')
const threshold = ref(0)
const alert = ref<LoginAlert | null>(null)
const handover = ref<HandoverResult | null>(null)
const errorMessage = ref('')
const notice = ref('')
const correction = ref<LoginEvent | null>(null)
const correctionValues = ref<Record<string, string>>({})
const correctionReason = ref('')

function fieldSummary(row: LoginEvent): string {
  return Object.entries(row.field_values)
    .filter(([key]) => row.observations.some((obs) => obs.field === key))
    .map(([key, value]) => `${key}=${value}`)
    .join(' / ') || '—'
}

function evidenceSummary(row: LoginEvent): string {
  return row.observations
    .map((obs) => `${obs.raw_value}→${obs.normalized ?? '待核'}${obs.conversion_evidence ? `（${obs.conversion_evidence}）` : ''}`)
    .join('；') || '—'
}

async function refresh(alertId: string) {
  alert.value = await getAlert(alertId)
}

async function runCheck() {
  errorMessage.value = ''
  notice.value = ''
  handover.value = null
  try {
    alert.value = await checkAlert(sourceId.value, threshold.value)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '告警计算失败'
  }
}

async function runDeliver(verificationAck: boolean) {
  if (!alert.value) return
  try {
    const result = await deliverAlert(alert.value.alert_id, verificationAck)
    await refresh(alert.value.alert_id)
    notice.value = `交付状态：${result.delivery_state}`
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '交付失败'
  }
}

async function runResume() {
  if (!alert.value) return
  try {
    const result = await resumeAlert(alert.value.alert_id) as {
      original: { already_sent: boolean; recount: boolean }
      amendments_delivered: unknown[]
      amendments_skipped: unknown[]
    }
    await refresh(alert.value.alert_id)
    notice.value = `恢复：原告警已送达=${result.original.already_sent}，重新计数=${result.original.recount}，`
      + `交付修正 ${result.amendments_delivered.length} 份，跳过已交付 ${result.amendments_skipped.length} 份`
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '恢复失败'
  }
}

async function runConfirm() {
  if (!alert.value) return
  try {
    const result = await confirmAlert(alert.value.alert_id)
    await refresh(alert.value.alert_id)
    notice.value = result.duplicate ? '该告警已确认过，不重复确认' : '交班确认已记录'
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '确认失败'
  }
}

async function runHandover() {
  if (!alert.value) return
  try {
    handover.value = await handoverAlert(alert.value.alert_id)
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '交班判定失败'
  }
}

function openCorrection(row: LoginEvent) {
  correction.value = row
  correctionValues.value = Object.fromEntries(
    row.observations.map((obs) => [obs.field, obs.raw_value]),
  )
  correctionReason.value = ''
}

async function submitCorrection() {
  if (!alert.value || !correction.value) return
  try {
    await correctEvent(alert.value.alert_id, {
      correction_id: `UI-${alert.value.alert_id}-${Date.now()}`,
      source_id: correction.value.source_id,
      line_number: correction.value.line_number,
      new_field_values: correctionValues.value,
      reason: correctionReason.value,
    })
    const alertId = alert.value.alert_id
    correction.value = null
    await refresh(alertId)
    notice.value = '更正已记录，只重算该事件及其告警'
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '更正失败'
  }
}
</script>
