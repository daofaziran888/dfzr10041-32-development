<template>
  <div class="app-shell">
    <aside class="app-side">
      <h1 class="app-title">拾音工坊 · 日志采集与事件流处理平台</h1>
      <nav class="nav-list">
        <RouterLink v-for="item in navItems" :key="item.path" :to="item.path" class="nav-item">
          {{ item.label }}
        </RouterLink>
      </nav>
    </aside>
    <main class="app-main">
      <header class="app-head">
        <span class="head-desc">面向多租户应用日志的结构化采集、事件流解析、格式标准化、敏感脱敏、采样归并、异常告警与归档回溯的日志采集与事件流处理平台。</span>
        <span class="head-user">当前值班：数据工程组</span>
      </header>
      <RouterView />
    </main>
  </div>
</template>

<script setup lang="ts">
const navItems = [{ label: "运营概览", path: "/" }, { label: "登录告警依据", path: "/login_alerts" }, { label: "日志源", path: "/log_source" }, { label: "解析规则", path: "/parser_rule" }, { label: "脱敏规则", path: "/mask_rule" }, { label: "事件分类", path: "/event_type" }, { label: "采集作业", path: "/ingest_job" }, { label: "批次检查点", path: "/batch_checkpoint" }, { label: "事件存储", path: "/event_store" }, { label: "异常告警", path: "/anomaly_rule" }, { label: "采样归并", path: "/sample_job" }, { label: "字段增强", path: "/field_enrich" }, { label: "归档策略", path: "/archive_policy" }, { label: "转发路由", path: "/forward_rule" }, { label: "Schema版本", path: "/schema_version" }, { label: "去重过滤", path: "/dedup_filter" }, { label: "采集指标", path: "/ingest_metric" }, { label: "事件重放", path: "/replay_record" }, { label: "质量报告", path: "/quality_report" }, { label: "标签分类", path: "/tag_taxonomy" }, { label: "打包导出", path: "/export_bundle" }, { label: "访问审计", path: "/audit_event" }, { label: "租户隔离", path: "/tenant_isolation" }, { label: "格式适配", path: "/format_adapt" }]
</script>
