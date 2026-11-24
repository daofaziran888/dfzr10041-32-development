# 拾音工坊 · 日志采集与事件流处理平台

面向多租户应用日志的结构化采集、事件流解析、格式标准化、敏感脱敏、采样归并、异常告警与归档回溯的日志采集与事件流处理平台。

这是一个前后端分离的管理平台：前端 Vue 3 + Vite + TypeScript，后端 FastAPI（Python）。
两边各自独立启动，前端 dev server 已关掉自动打开页面，启动后按终端打印的地址手工打开。

## 目录结构

```text
.
├── frontend/                 Vue 3 + Vite + TypeScript 前端
│   ├── src/views/WorkbenchView.vue|tsx  全部模块共享工作台
│   ├── src/data/modules.ts              18个业务模块配置
│   ├── src/api/              统一请求封装
│   └── vite.config.ts        dev server 配置（open: false）
├── backend/                  FastAPI（Python） 后端
│   ├── app/routers/resource.py  通用查询/导出/登记/动作接口
│   ├── app/services/<key>.py    每个模块独立领域逻辑
│   ├── app/services/base.py     共享服务骨架
│   ├── app/core/login_convention.py 登录动作换名、来源约定与带依据告警
│   ├── app/routers/login.py     登录约定/告警接口（固定路径先于通用路由）
│   └── app/store.py          内存数据仓库与示例数据
├── .gitignore
└── docker-compose.yml
```

## 启动

### 后端

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh
```

健康检查：`curl http://127.0.0.1:8000/api/health`

### 前端

```bash
cd frontend
npm ci
npm run dev
```

前端默认监听 `http://127.0.0.1:5173/`，dev server 不会自动打开浏览器，
需要自己访问。`/api` 由 vite 代理到后端 `http://127.0.0.1:8000`。

后端测试（无第三方测试框架，直接运行）：

```bash
cd backend
.venv/bin/python tests/test_login_convention.py
.venv/bin/python tests/test_ingest_pipeline.py
.venv/bin/python tests/test_dedup_sample.py
.venv/bin/python tests/test_mask_enrich.py
```

## 业务模块

| 模块 | 目录 | 业务对象 | 主要字段 |
| --- | --- | --- | --- |
| 日志源 | `log_source` | 日志来源 | 源编号、源名称、应用标识 |
| 解析规则 | `parser_rule` | 解析方案 | 方案编号、日志来源、正则表达式 |
| 脱敏规则 | `mask_rule` | 脱敏配置 | 规则编号、目标字段、脱敏方式 |
| 事件分类 | `event_type` | 事件类型 | 类型编号、类型名称、分类标签 |
| 采集作业 | `ingest_job` | 采集任务 | 作业编号、日志来源、采集模式 |
| 批次检查点 | `batch_checkpoint` | 检查点记录 | 记录编号、采集作业、文件路径 |
| 事件存储 | `event_store` | 事件记录 | 记录编号、事件类型、原始内容 |
| 异常告警 | `anomaly_rule` | 告警规则 | 规则编号、事件类型、检测条件 |
| 采样归并 | `sample_job` | 采样计划 | 计划编号、事件类型、采样比例 |
| 字段增强 | `field_enrich` | 增强规则 | 规则编号、目标字段、增强来源 |
| 归档策略 | `archive_policy` | 归档方案 | 方案编号、事件类型、保留天数 |
| 转发路由 | `forward_rule` | 转发规则 | 规则编号、事件类型、目标地址 |
| Schema版本 | `schema_version` | 版本记录 | 版本编号、日志来源、字段变更 |
| 去重过滤 | `dedup_filter` | 去重规则 | 规则编号、事件类型、去重字段 |
| 采集指标 | `ingest_metric` | 指标记录 | 记录编号、日志来源、采集速率 |
| 事件重放 | `replay_record` | 重放任务 | 任务编号、来源事件、重放范围 |
| 质量报告 | `quality_report` | 质量评估 | 报告编号、日志来源、完整率 |
| 标签分类 | `tag_taxonomy` | 标签定义 | 标签编号、标签名称、父级标签 |
| 打包导出 | `export_bundle` | 导出包 | 包编号、事件类型、时间范围 |
| 访问审计 | `audit_event` | 审计记录 | 记录编号、操作模块、操作人 |
| 租户隔离 | `tenant_isolation` | 租户配置 | 租户编号、租户名称、日志来源 |
| 格式适配 | `format_adapt` | 适配器配置 | 适配器编号、输入格式、输出格式 |

## 登录动作换名与来源约定

访问日志里的登录动作在不同来源中叫法不同（`LOGIN` / `SIGN_IN` / `verb` …），
只靠字段改名不能说明语义相同。`backend/app/core/login_convention.py` 把三件事分开：

1. **字段改名**：`renames` 声明旧字段名到规范字段名，`groups` 声明哪些字段承载动作值。
2. **取值转换**：每个原动作值到 `LOGIN`/`LOGOUT`/`ACCESS` 的映射必须带可复核 `evidence`。
3. **告警依据**：每条参与告警的事件保留原行、字段组、原值、转换依据和字段版本。

硬性规则：

- 只有 `生效中` 的来源约定参与判定；草稿约定给出 `INACTIVE`。
- 缺转换依据的 `SIGN_IN` 导入即拒绝，分类时只留待核对，不默认成 `LOGIN`。
- 普通请求方法（GET/POST…）不能通过字段改名变成 `LOGIN`/`LOGOUT`。
- 同一原行两个字段给出不同动作值 → `CONFLICT`，两个原值都留在依据里，且不计入告警。
- 未登记的新动作 → `UNKNOWN`，不因为字段名相同就参与告警。
- 不同来源各自的约定独立生效：甲的 `verb=LOGIN` 是登录，乙的 `verb=LOGIN` 可能只是访问标签。
- 更正按 `correction_id` 幂等，只重算该事件及其告警，不扫描同批其它来源。
- 已送达告警的修正单独关联（`amendments`），恢复时原告警不重发、不重新计数，
  应交付的修正不跳过；同一告警交班确认跨进程只允许一次（原子标记文件）。
- 已确认告警按当时实际使用的字段版本重算，新版约定下的计数单独给出，
  旧名字原行不能自动沿用成新告警。

接口（固定路径排在通用 `/{module}` 之前）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/login/conventions/validate` | 只核对转换表与依据，不导入 |
| POST | `/api/login/conventions` | 导入来源约定（保留历史版本） |
| GET | `/api/login/conventions` | 列出各来源约定版本 |
| GET | `/api/login/conventions/{source_id}` | 查看可复核的约定快照 |
| POST | `/api/login/events/classify` | 按来源约定分类并返回登录依据 |
| POST | `/api/login/alerts/check` | 用实际有效候选计数，生成带依据告警 |
| GET | `/api/login/alerts/{alert_id}/audit` | 核对参与原行、字段版本、矛盾原值与复核清单 |
| GET | `/api/login/alerts/{alert_id}/handover` | 本轮能否完成：历史口径与下一轮真实计数 |
| POST | `/api/login/corrections` | 值班员更正原行，只重算该事件及告警 |
| POST | `/api/login/alerts/deliver` | 交付告警，字段核验端未确认时保留中断状态 |
| POST | `/api/login/alerts/{alert_id}/resume` | 中断后恢复，不重发原告警、交付待交付修正 |
| POST | `/api/login/alerts/{alert_id}/confirm` | 交班确认，同一告警只允许一次 |

前端新增「登录告警依据」页（`/login_alerts`），可查看参与告警的原行与字段组、
未计入原因、修正关联、交付/恢复结果与交班判定。

`IngestPipeline.classify_events` 与 `IngestPipeline.check_anomaly` 遵守同一判定规则：
分类时按来源生效条件和换名兼容规则给出登录事件；计数时只统计实际有效候选。


## 约定

- 全部模块共享`frontend/src/views/WorkbenchView.vue|tsx`和一套资源路由。
- 每个模块仍保留独立`backend/app/services/<模块>.py`；纯前端保留
  `frontend/src/domain/<模块>.ts`，用于承载真实业务差异并维持36题位容量。
- 列表接口统一返回 `{ items, total, page, size }`，动作接口统一返回 `{ ok, message }`。
- 状态流转只允许在 `app/services` 里改，路由层不做业务判断。

领域：数据工程
子方向：数据采集、爬虫与RPA
