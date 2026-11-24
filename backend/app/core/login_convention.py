"""来源约定：登录动作换名、字段取值转换与带依据的登录告警。

访问日志的登录动作在不同来源里有不同叫法（``LOGIN`` / ``SIGN_IN`` / ``verb`` …）。
只把字段改名并不能说明语义相同，因此本模块把三件事分开保存、分别校验：

1. **字段改名**：来源约定声明哪些字段承载动作值，以及旧字段名到规范字段名的改名。
2. **取值转换**：每个原动作值到规范动作（LOGIN/LOGOUT/ACCESS）的映射，必须带可复核依据。
3. **告警依据**：每条参与告警的事件都保留原行、字段组、原值、转换依据与字段版本。

设计约束（与业务口径一一对应）：

* 只有 ``生效中`` 的来源约定参与分类；草稿约定给出 ``INACTIVE``。
* 缺少转换依据的 ``SIGN_IN`` 不会被默认成 ``LOGIN``；导入阶段直接拒绝。
* 普通请求方法（GET/POST/…）不允许被配置成 LOGIN/LOGOUT。
* 同一条原行两个字段给出不同动作值时判为 ``CONFLICT``，不得计入登录告警。
* 未登记的新动作判为 ``UNKNOWN`` 留待核对，不因为字段名相同就参与告警。
* 更正只重算被更正的那条事件及引用它的告警，不扫描/重算同批其他来源。
* 同一更正按 ``correction_id`` 幂等；同一告警交班确认跨进程只允许一次。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field as dc_field
from datetime import datetime
from typing import Any, Iterable

# ---------- 规范动作 ----------

LOGIN = "LOGIN"
LOGOUT = "LOGOUT"
ACCESS = "ACCESS"
UNKNOWN = "UNKNOWN"
CONFLICT = "CONFLICT"
INACTIVE = "INACTIVE"

NORMALIZED_ACTIONS = {LOGIN, LOGOUT, ACCESS}

# 普通 HTTP 请求方法：可以映射为 ACCESS，但绝不能换名成 LOGIN/LOGOUT。
ORDINARY_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)


def _norm(value: Any) -> str:
    return str(value or "").strip()


# ---------- 约定本身 ----------


@dataclass(frozen=True)
class ValueConversion:
    """一个原动作值到规范动作的转换，必须能回查依据。"""

    raw_value: str                 # 日志里真实出现的值，如 SIGN_IN / LOGIN / GET
    normalized: str                # LOGIN / LOGOUT / ACCESS
    evidence: str = ""             # 真实动作值转换依据（文档、工单、样例行）
    field_name: str = ""           # 空串表示对约定里的任意动作字段生效
    note: str = ""

    def as_evidence(self) -> dict[str, Any]:
        return {
            "raw_value": self.raw_value,
            "normalized": self.normalized,
            "evidence": self.evidence,
            "field_name": self.field_name,
            "note": self.note,
        }


@dataclass(frozen=True)
class LoginFieldGroup:
    """一组承载登录动作的字段（允许换名后的多个字段）。"""

    group_id: str
    fields: tuple[str, ...]
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "fields": list(self.fields),
            "description": self.description,
        }


@dataclass
class SourceConvention:
    """某个日志来源在一段时期内生效的登录字段约定。"""

    source_id: str
    version: str
    state: str = "生效中"                      # 生效中 / 草稿 / 已停用
    groups: list[LoginFieldGroup] = dc_field(default_factory=list)
    conversions: list[ValueConversion] = dc_field(default_factory=list)
    renames: dict[str, str] = dc_field(default_factory=dict)  # 旧字段名 -> 规范字段名
    description: str = ""
    effective_from: str = ""
    created_at: str = dc_field(default_factory=_now)

    # ----- 查询 -----

    def lookup(self, field_name: str, raw_value: str) -> ValueConversion | None:
        """按字段名 + 原值查转换：字段专属优先于通用转换。"""
        raw = _norm(raw_value)
        if not raw:
            return None
        candidates: list[ValueConversion] = []
        for conversion in self.conversions:
            if _norm(conversion.raw_value).casefold() != raw.casefold():
                continue
            if conversion.field_name in ("", field_name):
                candidates.append(conversion)
        if not candidates:
            return None
        candidates.sort(key=lambda item: 0 if item.field_name else 1)
        return candidates[0]

    def canonical_field(self, field_name: str) -> str:
        return self.renames.get(field_name, field_name)

    def conversion_table(self) -> list[dict[str, Any]]:
        return [conversion.as_evidence() for conversion in self.conversions]

    def snapshot(self) -> dict[str, Any]:
        """可复核的约定快照；历史告警按它重算。"""
        return {
            "source_id": self.source_id,
            "version": self.version,
            "state": self.state,
            "description": self.description,
            "effective_from": self.effective_from,
            "groups": [group.as_dict() for group in self.groups],
            "renames": dict(self.renames),
            "conversions": self.conversion_table(),
            "created_at": self.created_at,
        }

    # ----- 导入校验 -----

    def validate(self) -> dict[str, Any]:
        """核对真实动作值转换表。

        返回可供值班员/负责人直接查看的报告：
        - ``errors``：必须修复，报告为不可导入；
        - ``warnings``：可导入但需留档；
        - ``collisions``：两个不同原动作配成同一动作时的原值与依据；
        - ``missing_evidence``：缺少转换依据的登录动作；
        - ``ordinary_conflicts``：把普通请求方法配成登录动作。
        """
        errors: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        missing_evidence: list[dict[str, Any]] = []
        ordinary_conflicts: list[dict[str, Any]] = []
        collisions: dict[str, list[dict[str, Any]]] = {}

        if not _norm(self.source_id):
            errors.append({"code": "missing_source", "message": "来源编号不能为空"})
        if not _norm(self.version):
            errors.append({"code": "missing_version", "message": "约定版本不能为空"})
        if not self.groups:
            errors.append({"code": "missing_field_group", "message": "至少需要一组登录动作字段"})

        seen_fields: set[str] = set()
        group_fields: set[str] = set()
        for group in self.groups:
            if not group.fields:
                errors.append({
                    "code": "empty_field_group",
                    "message": f"字段组 {group.group_id} 没有字段",
                })
            for field_name in group.fields:
                group_fields.add(field_name)
                if field_name in seen_fields:
                    warnings.append({
                        "code": "duplicate_field",
                        "message": f"字段 {field_name} 在多个字段组中重复出现",
                        "field": field_name,
                    })
                seen_fields.add(field_name)

        for old_name, canonical in self.renames.items():
            if not _norm(canonical):
                errors.append({
                    "code": "empty_rename_target",
                    "message": f"字段 {old_name} 的改名目标为空",
                    "field": old_name,
                })
            elif canonical not in group_fields:
                warnings.append({
                    "code": "rename_target_outside_group",
                    "message": f"字段 {old_name} 改名后指向 {canonical}，但目标字段不在同一字段组",
                    "field": old_name,
                })

        # 原值 -> 规范动作 的索引（同字段范围内）
        by_scope: dict[tuple[str, str], list[ValueConversion]] = {}
        for conversion in self.conversions:
            raw = _norm(conversion.raw_value)
            normalized = _norm(conversion.normalized).upper()
            if not raw:
                errors.append({"code": "missing_raw_value", "message": "转换表存在空的原动作值"})
                continue
            if normalized not in NORMALIZED_ACTIONS:
                errors.append({
                    "code": "invalid_normalized_action",
                    "message": f"原动作 {raw} 的目标动作 {conversion.normalized} 不在允许范围",
                    "raw_value": raw,
                    "normalized": conversion.normalized,
                })
                continue
            if normalized in (LOGIN, LOGOUT) and not _norm(conversion.evidence):
                item = {
                    "code": "missing_conversion_evidence",
                    "message": f"原动作 {raw} 缺少转换依据，不能默认分类为 {normalized}",
                    "raw_value": raw,
                    "normalized": normalized,
                    "field_name": conversion.field_name,
                }
                missing_evidence.append(item)
                errors.append(item)
            if normalized in (LOGIN, LOGOUT) and raw.upper() in ORDINARY_METHODS:
                item = {
                    "code": "ordinary_method_as_login",
                    "message": f"普通请求方法 {raw} 不能通过字段改名变成 {normalized}",
                    "raw_value": raw,
                    "normalized": normalized,
                    "field_name": conversion.field_name,
                }
                ordinary_conflicts.append(item)
                errors.append(item)
            by_scope.setdefault((conversion.field_name, raw.casefold()), []).append(conversion)
            collisions.setdefault(normalized, []).append(conversion.as_evidence())
            if conversion.field_name and conversion.field_name not in group_fields \
                    and conversion.field_name not in self.renames:
                warnings.append({
                    "code": "conversion_field_outside_group",
                    "message": f"原动作 {raw} 指定的字段 {conversion.field_name} 不在任何登录动作字段组中",
                    "raw_value": raw,
                    "field_name": conversion.field_name,
                })

        # 同一字段 + 同一原值却配出两个目标动作：必须拒绝。
        for (field_name, raw_key), entries in by_scope.items():
            targets = {_norm(item.normalized).upper() for item in entries}
            if len(targets) > 1:
                errors.append({
                    "code": "conflicting_conversion",
                    "message": f"原动作 {raw_key} 被配置成多个目标动作",
                    "raw_value": raw_key,
                    "field_name": field_name,
                    "targets": sorted(targets),
                    "evidence": [item.as_evidence() for item in entries],
                })

        # 不同原动作配成同一动作：不算错误，但必须能从 collisions 回查原值与依据。
        shared_targets = {
            action: table for action, table in collisions.items()
            if len({_norm(row["raw_value"]).casefold() for row in table}) > 1
        }
        for action, table in shared_targets.items():
            warnings.append({
                "code": "shared_normalized_action",
                "message": f"多个不同原动作都被配置为 {action}，请确认它们语义一致",
                "normalized": action,
                "raw_values": sorted({row["raw_value"] for row in table}),
                "evidence": table,
            })

        return {
            "ok": not errors,
            "source_id": self.source_id,
            "version": self.version,
            "state": self.state,
            "errors": errors,
            "warnings": warnings,
            "missing_evidence": missing_evidence,
            "ordinary_conflicts": ordinary_conflicts,
            "collisions": {
                action: table for action, table in sorted(collisions.items())
            },
            "conversion_table": self.conversion_table(),
        }


# ---------- 约定注册表（保留历史版本） ----------


class LoginConventionRegistry:
    """按来源保存约定版本；历史版本只读保留，供已确认告警按原口径重算。"""

    def __init__(self) -> None:
        self._versions: dict[tuple[str, str], SourceConvention] = {}
        self._active: dict[str, str] = {}
        self._lock = threading.RLock()

    def import_convention(self, convention: SourceConvention | dict[str, Any]) -> dict[str, Any]:
        if isinstance(convention, dict):
            convention = convention_from_payload(convention)
        report = convention.validate()
        report["registered"] = False
        if not report["ok"]:
            return report
        key = (convention.source_id, convention.version)
        with self._lock:
            existing = self._versions.get(key)
            if existing is not None:
                if existing.snapshot() != convention.snapshot():
                    report["ok"] = False
                    report["errors"].append({
                        "code": "version_conflict",
                        "message": f"{convention.source_id} 已存在内容不同的版本 {convention.version}",
                    })
                    return report
                report["registered"] = True
                report["duplicate_version"] = True
            else:
                self._versions[key] = convention
                report["registered"] = True
                report["duplicate_version"] = False
            if convention.state == "生效中":
                self._active[convention.source_id] = convention.version
        report["active_version"] = self._active.get(convention.source_id, "")
        return report

    def get(self, source_id: str, version: str | None = None) -> SourceConvention | None:
        with self._lock:
            selected = version or self._active.get(source_id)
            if not selected:
                return None
            return self._versions.get((source_id, selected))

    def active(self, source_id: str) -> SourceConvention | None:
        return self.get(source_id)

    def versions(self, source_id: str) -> list[str]:
        with self._lock:
            return sorted(
                version for (sid, version) in self._versions if sid == source_id
            )

    def all_versions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "source_id": source_id,
                    "version": version,
                    "state": convention.state,
                    "active": self._active.get(source_id) == version,
                }
                for (source_id, version), convention in sorted(self._versions.items())
            ]

    def clear(self) -> None:
        with self._lock:
            self._versions.clear()
            self._active.clear()


def convention_from_payload(payload: dict[str, Any]) -> SourceConvention:
    groups = [
        LoginFieldGroup(
            group_id=str(group.get("group_id") or f"G{index + 1}"),
            fields=tuple(str(field) for field in group.get("fields", [])),
            description=str(group.get("description") or ""),
        )
        for index, group in enumerate(payload.get("groups") or [])
    ]
    conversions = [
        ValueConversion(
            raw_value=str(item.get("raw_value") or ""),
            normalized=str(item.get("normalized") or "").upper(),
            evidence=str(item.get("evidence") or ""),
            field_name=str(item.get("field_name") or ""),
            note=str(item.get("note") or ""),
        )
        for item in payload.get("conversions") or []
    ]
    return SourceConvention(
        source_id=str(payload.get("source_id") or ""),
        version=str(payload.get("version") or ""),
        state=str(payload.get("state") or "生效中"),
        groups=groups,
        conversions=conversions,
        renames={str(k): str(v) for k, v in (payload.get("renames") or {}).items()},
        description=str(payload.get("description") or ""),
        effective_from=str(payload.get("effective_from") or ""),
    )


# ---------- 分类 ----------


@dataclass
class LoginEvent:
    """一条带登录判定依据的事件（由 LogEntry/EventRecord 派生）。"""

    record_id: str
    source_id: str
    line_number: int
    raw_line: str
    verdict: str = UNKNOWN
    field_group: str = ""
    field_values: dict[str, str] = dc_field(default_factory=dict)
    observations: list[dict[str, Any]] = dc_field(default_factory=list)
    review_reason: str = ""
    effective: bool = False
    field_version: str = ""
    convention_version: str = ""
    event_type_id: str = ""
    revised: bool = False

    @property
    def key(self) -> str:
        return event_key(self.source_id, self.line_number, self.record_id)

    def evidence_row(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "source_id": self.source_id,
            "line_number": self.line_number,
            "raw_line": self.raw_line,
            "field_group": self.field_group,
            "field_values": dict(self.field_values),
            "verdict": self.verdict,
            "observations": self.observations,
            "review_reason": self.review_reason,
            "field_version": self.field_version,
            "convention_version": self.convention_version,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.evidence_row() | {
            "event_type_id": self.event_type_id,
            "effective": self.effective,
            "revised": self.revised,
        }


def event_key(source_id: str, line_number: int, record_id: str = "") -> str:
    """一条原行事件的稳定键：来源 + 行号 + 记录号，避免同一来源不同主机撞号。"""
    return f"{source_id}|L{line_number}|{record_id}"


def classify_with_convention(
    convention: SourceConvention | None,
    source_id: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    """按来源约定判定一条原行的动作语义。

    返回 ``verdict`` / ``effective`` / ``field_group`` / ``observations`` /
    ``review_reason`` 以及字段版本，供事件与告警复用同一判定规则。
    """
    empty = {
        "verdict": UNKNOWN,
        "effective": False,
        "field_group": "",
        "observations": [],
        "review_reason": "来源没有生效中的登录约定",
        "field_version": "",
        "convention_version": "",
    }
    if convention is None:
        return empty
    if convention.source_id != source_id:
        return empty | {"review_reason": "来源与约定不匹配"}
    if convention.state != "生效中":
        return empty | {
            "verdict": INACTIVE,
            "review_reason": f"来源约定状态为 {convention.state}，不参与登录判定",
            "field_version": convention.version,
            "convention_version": convention.version,
        }

    group_results: list[dict[str, Any]] = []
    for group in convention.groups:
        observations: list[dict[str, Any]] = []
        for field_name in group.fields:
            # 换名兼容：规范字段优先；规范字段缺省时回退到声明过的旧字段名。
            alias_fields = [
                old for old, canonical in convention.renames.items()
                if canonical == field_name and old in fields
            ]
            source_field = field_name
            if not _norm(fields.get(field_name)) and alias_fields:
                source_field = alias_fields[0]
            raw_value = _norm(fields.get(source_field))
            if not raw_value:
                continue
            canonical = convention.canonical_field(source_field)
            conversion = (
                convention.lookup(source_field, raw_value)
                or convention.lookup(field_name, raw_value)
                or convention.lookup(canonical, raw_value)
            )
            observation: dict[str, Any] = {
                "field": source_field,
                "canonical_field": canonical,
                "raw_value": raw_value,
                "field_renamed": source_field != field_name or canonical != field_name,
            }
            if conversion is not None:
                normalized = _norm(conversion.normalized).upper()
                observation.update({
                    "normalized": normalized,
                    "conversion_evidence": conversion.evidence,
                })
                if normalized in (LOGIN, LOGOUT) and not _norm(conversion.evidence):
                    observation["normalized"] = None
                    observation["pending_reason"] = "缺少转换依据，不能默认分类"
            elif raw_value.upper() in ORDINARY_METHODS:
                observation.update({
                    "normalized": ACCESS,
                    "conversion_evidence": "普通请求方法，按访问处理",
                })
            else:
                observation.update({
                    "normalized": None,
                    "pending_reason": "未登记的新动作，留待核对",
                })
            observations.append(observation)

        recognized = {
            obs["normalized"] for obs in observations if obs.get("normalized")
        }
        pending = [
            obs for obs in observations if obs.get("normalized") is None
        ]
        group_results.append({
            "group": group,
            "observations": observations,
            "recognized": recognized,
            "pending": pending,
        })

    definitive = [
        result for result in group_results
        if result["recognized"] and not result["pending"]
    ]

    def build(group_result: dict[str, Any], verdict: str, reason: str) -> dict[str, Any]:
        return {
            "verdict": verdict,
            "effective": verdict == LOGIN,
            "field_group": group_result["group"].group_id,
            "observations": group_result["observations"],
            "review_reason": reason,
            "field_version": convention.version,
            "convention_version": convention.version,
        }

    # 只有同一字段组内出现两个可识别且不一致的原值，才是双字段矛盾。
    # “一个可识别 + 一个未登记”属于部分可判定：可识别部分照常判定，
    # 未登记值单独留待核对，不因此把整条原行判成冲突。
    conflict_groups = [
        result for result in group_results
        if len(result["recognized"]) > 1
    ]
    pending_alongside = [
        result for result in group_results
        if result["recognized"] and result["pending"]
    ]

    if conflict_groups:
        merged_observations = [
            obs for result in conflict_groups for obs in result["observations"]
        ]
        return {
            "verdict": CONFLICT,
            "effective": False,
            "field_group": conflict_groups[0]["group"].group_id,
            "observations": merged_observations,
            "review_reason": "同一原行的动作字段取值矛盾",
            "field_version": convention.version,
            "convention_version": convention.version,
        }

    if len(definitive) > 1:
        verdicts = {
            next(iter(result["recognized"])) for result in definitive
        }
        if len(verdicts) == 1:
            merged = [
                obs for result in definitive for obs in result["observations"]
            ]
            verdict = verdicts.pop()
            return {
                "verdict": verdict,
                "effective": verdict == LOGIN,
                "field_group": definitive[0]["group"].group_id,
                "observations": merged,
                "review_reason": "",
                "field_version": convention.version,
                "convention_version": convention.version,
            }
        merged = [obs for result in definitive for obs in result["observations"]]
        return {
            "verdict": CONFLICT,
            "effective": False,
            "field_group": definitive[0]["group"].group_id,
            "observations": merged,
            "review_reason": "多个字段组给出不同动作",
            "field_version": convention.version,
            "convention_version": convention.version,
        }

    if definitive:
        result = definitive[0]
        verdict = next(iter(result["recognized"]))
        return build(result, verdict, "")

    # 没有可确认的 definitive 组：若有“可识别 + 未登记/缺依据”的组，
    # 可识别部分照常判定（登录/登出/访问），待核项单独留在 observations/review_reason。
    if pending_alongside:
        result = pending_alongside[0]
        verdict = next(iter(result["recognized"]))
        pending_notes = "；".join(
            sorted({obs.get("pending_reason", "") for obs in result["pending"]})
        )
        payload = build(result, verdict, pending_notes)
        payload["unregistered_values"] = [
            obs["raw_value"] for obs in result["pending"]
        ]
        return payload

    # 完全没有可识别的动作：区分“留待核对”和“纯访问”。
    pending_results = [result for result in group_results if result["pending"]]
    if pending_results:
        result = pending_results[0]
        reason = "；".join(
            sorted({obs.get("pending_reason", "") for obs in result["pending"]})
        )
        return build(result, UNKNOWN, reason)

    observations = [
        obs for result in group_results for obs in result["observations"]
    ]
    return {
        "verdict": ACCESS,
        "effective": False,
        "field_group": group_results[0]["group"].group_id if group_results else "",
        "observations": observations,
        "review_reason": "",
        "field_version": convention.version,
        "convention_version": convention.version,
    }


# ---------- 告警与修正 ----------


@dataclass
class LoginAlert:
    """带依据的登录告警；计数只来自实际有效的 LOGIN 候选。"""

    alert_id: str
    source_id: str
    event_type_id: str
    threshold: int
    convention_version: str
    field_group: str = ""
    count: int = 0
    triggered: bool = False
    event_keys: list[str] = dc_field(default_factory=list)
    candidate_keys: list[str] = dc_field(default_factory=list)
    evidence: list[dict[str, Any]] = dc_field(default_factory=list)
    excluded: list[dict[str, Any]] = dc_field(default_factory=list)
    delivered: bool = False
    delivered_target: str = ""
    delivery_state: str = "未送达"            # 未送达 / 已送达待确认 / 已送达已确认
    acked_endpoints: dict[str, bool] = dc_field(default_factory=dict)
    interruption: dict[str, Any] = dc_field(default_factory=dict)
    amendments: list[dict[str, Any]] = dc_field(default_factory=list)
    confirmed: bool = False
    confirmed_version: str = ""
    confirmed_at: str = ""
    created_at: str = dc_field(default_factory=_now)

    def to_dict(self, *, include_evidence: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "alert_id": self.alert_id,
            "source_id": self.source_id,
            "event_type_id": self.event_type_id,
            "threshold": self.threshold,
            "count": self.count,
            "triggered": self.triggered,
            "convention_version": self.convention_version,
            "field_version": self.convention_version,
            "field_group": self.field_group,
            "delivered": self.delivered,
            "delivered_target": self.delivered_target,
            "delivery_state": self.delivery_state,
            "acked_endpoints": dict(self.acked_endpoints),
            "interruption": dict(self.interruption),
            "confirmed": self.confirmed,
            "confirmed_version": self.confirmed_version,
            "confirmed_at": self.confirmed_at,
            "created_at": self.created_at,
            "excluded_count": len(self.excluded),
            "excluded": self.excluded,
            "amendment_count": len(self.amendments),
            "amendments": self.amendments,
        }
        if include_evidence:
            payload["evidence"] = self.evidence
            payload["participating_rows"] = [
                row["raw_line"] for row in self.evidence
            ]
        return payload


class LoginAlertEngine:
    """登录事件的判定、告警计数、更正重算与交付/交班状态机。"""

    def __init__(
        self,
        registry: LoginConventionRegistry | None = None,
        handover_dir: str | None = None,
    ) -> None:
        self.registry = registry or LoginConventionRegistry()
        self.events: dict[str, LoginEvent] = {}
        self.alerts: dict[str, LoginAlert] = {}
        self._corrections: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._handover_dir = handover_dir or os.path.join(
            tempfile.gettempdir(), "pickup_handover",
        )

    # ----- 事件登记与分类 -----

    def classify_entry(
        self,
        *,
        source_id: str,
        line_number: int,
        raw_line: str,
        fields: dict[str, Any],
        record_id: str = "",
        event_type_id: str = "",
        convention: SourceConvention | None = None,
    ) -> LoginEvent:
        convention = convention or self.registry.active(source_id)
        result = classify_with_convention(convention, source_id, fields)
        event = LoginEvent(
            record_id=record_id or f"{source_id}-L{line_number}",
            source_id=source_id,
            line_number=line_number,
            raw_line=raw_line,
            verdict=result["verdict"],
            field_group=result["field_group"],
            field_values={
                key: _norm(value) for key, value in fields.items()
                if _norm(value)
            },
            observations=result["observations"],
            review_reason=result["review_reason"],
            effective=result["effective"],
            field_version=result["field_version"],
            convention_version=result["convention_version"],
            event_type_id=event_type_id,
        )
        with self._lock:
            self.events[event.key] = event
        return event

    # ----- 告警计数 -----

    def check(
        self,
        *,
        source_id: str,
        event_type_id: str,
        threshold: int,
        event_keys: Iterable[str] | None = None,
        alert_id: str | None = None,
    ) -> LoginAlert:
        """按实际有效候选计数并生成/刷新告警。

        只有 ``verdict == LOGIN`` 且 ``effective`` 的事件参与计数。
        ``CONFLICT``、``UNKNOWN``、``ACCESS``、``LOGOUT``、``INACTIVE``
        以及其它来源的记录全部进入 ``excluded``，并保留原行与原因。
        """
        selected_keys = list(event_keys) if event_keys is not None else None
        with self._lock:
            candidates = [
                event for key, event in self.events.items()
                if selected_keys is None or key in selected_keys
            ]
            existing = self.alerts.get(alert_id) if alert_id else None
            if existing is not None:
                pinned_version = existing.convention_version
            else:
                # 新建告警时按来源当前生效约定定口径；不能因为候选里
                # 恰好有旧版本事件就把新告警建到旧版本上。
                active = self.registry.active(source_id)
                pinned_version = active.version if active is not None else ""
        effective: list[LoginEvent] = []
        excluded: list[dict[str, Any]] = []
        for event in candidates:
            if event.source_id != source_id:
                excluded.append(_excluded_row(event, "other_source", "非本来源，不参与本来源告警"))
                continue
            if pinned_version and event.convention_version and event.convention_version != pinned_version:
                # 既有告警不静默混用新约定事件：保留历史口径，单独列出。
                excluded.append(_excluded_row(
                    event, "convention_version_mismatch",
                    f"事件字段版本 {event.convention_version} 与告警口径 {pinned_version} 不一致，未计入",
                ))
                continue
            if event.verdict == LOGIN and event.effective:
                effective.append(event)
            elif event.verdict == CONFLICT:
                excluded.append(_excluded_row(event, "field_conflict", "双字段取值矛盾，不能计入"))
            elif event.verdict == UNKNOWN:
                excluded.append(_excluded_row(event, "pending_review", event.review_reason or "待核对动作"))
            elif event.verdict == LOGOUT:
                excluded.append(_excluded_row(event, "logout", "登出动作不计入登录告警"))
            elif event.verdict == INACTIVE:
                excluded.append(_excluded_row(event, "inactive_convention", event.review_reason))
            else:
                excluded.append(_excluded_row(event, "not_login", event.review_reason or "非登录动作"))

        convention_version = (
            pinned_version
            or (effective[0].convention_version if effective
                else (candidates[0].convention_version if candidates else ""))
        )
        field_group = effective[0].field_group if effective else (
            candidates[0].field_group if candidates else ""
        )
        if alert_id is None:
            alert_id = "LA-{}-{}".format(
                _safe_id(source_id),
                _safe_id(convention_version or "none"),
            )
            alert_id = f"{alert_id}-T{threshold}"

        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                alert = LoginAlert(
                    alert_id=alert_id,
                    source_id=source_id,
                    event_type_id=event_type_id,
                    threshold=threshold,
                    convention_version=convention_version,
                    field_group=field_group,
                )
                self.alerts[alert_id] = alert
            elif alert.convention_version and convention_version and alert.convention_version != convention_version:
                # 兜底：仍不允许把候选事件的字段版本混进既有告警。
                excluded.append({
                    "reason": "convention_version_mismatch",
                    "message": "候选事件来自不同约定版本，未计入既有告警",
                    "alert_convention_version": alert.convention_version,
                    "event_convention_version": convention_version,
                })
            alert.event_type_id = event_type_id
            alert.threshold = threshold
            alert.candidate_keys = [event.key for event in candidates]
            alert.event_keys = [event.key for event in effective]
            alert.evidence = [event.evidence_row() for event in effective]
            alert.excluded = excluded
            alert.count = len(effective)
            alert.triggered = alert.count > threshold
            if alert.field_group == "" and field_group:
                alert.field_group = field_group
            if alert.convention_version == "" and convention_version:
                alert.convention_version = convention_version
            return alert

    # ----- 值班员更正 -----

    def correct(
        self,
        *,
        correction_id: str,
        source_id: str,
        new_field_values: dict[str, Any],
        reason: str = "",
        record_id: str = "",
        line_number: int | None = None,
        convention_version: str | None = None,
    ) -> dict[str, Any]:
        """更正某条原行的动作值，只重算这条事件及其影响的告警。

        幂等：同一 ``correction_id`` 重放直接返回首次结果，不追加第二份事件/修正。
        """
        with self._lock:
            if correction_id in self._corrections:
                replay = dict(self._corrections[correction_id])
                replay["duplicate"] = True
                return replay

            event = self._find_event(source_id, record_id, line_number)
            if event is None:
                return {
                    "ok": False,
                    "duplicate": False,
                    "message": "未找到需要更正的原行事件",
                    "correction_id": correction_id,
                }

            related_alerts = [
                alert for alert in self.alerts.values()
                if event.key in alert.event_keys or event.key in alert.candidate_keys
            ]
            # 已送达/已确认的告警按实际使用的历史口径重算；否则用当前生效约定。
            historical_version = (
                convention_version
                or (related_alerts[0].convention_version if related_alerts else "")
                or event.convention_version
            )
            convention = self.registry.get(source_id, historical_version or None)

            before = event.to_dict()
            merged_fields = dict(event.field_values)
            merged_fields.update({
                key: _norm(value) for key, value in new_field_values.items()
            })
            result = classify_with_convention(convention, source_id, merged_fields)

            event.field_values = {
                key: _norm(value) for key, value in merged_fields.items()
                if _norm(value)
            }
            event.verdict = result["verdict"]
            event.effective = result["effective"]
            event.field_group = result["field_group"] or event.field_group
            event.observations = result["observations"]
            event.review_reason = result["review_reason"]
            event.field_version = result["field_version"] or event.field_version
            event.convention_version = result["convention_version"] or event.convention_version
            event.revised = True

            amendment = {
                "kind": "event_correction",
                "correction_id": correction_id,
                "record_id": event.record_id,
                "source_id": source_id,
                "line_number": event.line_number,
                "raw_line": event.raw_line,
                "reason": reason,
                "convention_version": event.convention_version,
                "field_version": event.field_version,
                "field_group": event.field_group,
                "before": before,
                "after": event.to_dict(),
                "basis": {
                    "changed_fields": {
                        key: {
                            "before": before.get("field_values", {}).get(key, ""),
                            "after": _norm(value),
                        }
                        for key, value in new_field_values.items()
                    },
                    "conversion_evidence": [
                        obs for obs in event.observations
                        if obs.get("conversion_evidence")
                    ],
                    "review_reason": event.review_reason,
                },
                "delivered": False,
                "delivered_at": "",
            }

            affected: list[dict[str, Any]] = []
            for alert in related_alerts:
                # 只在该告警自己的候选事件里重算：不扫描同批其它来源，也不并入新事件。
                refreshed = [
                    self.events[key] for key in alert.candidate_keys
                    if key in self.events
                ]
                if not any(item.key == event.key for item in refreshed):
                    refreshed.append(event)
                effective_now = [
                    item for item in refreshed
                    if item.effective and item.verdict == LOGIN
                ]
                excluded_now = [
                    _excluded_row(item, _exclusion_reason(item), _exclusion_message(item))
                    for item in refreshed
                    if not (item.effective and item.verdict == LOGIN)
                ]
                alert.candidate_keys = [item.key for item in refreshed]
                alert.event_keys = [item.key for item in effective_now]
                alert.evidence = [item.evidence_row() for item in effective_now]
                alert.excluded = excluded_now
                alert.count = len(effective_now)
                alert.triggered = alert.count > alert.threshold
                linked = dict(amendment)
                linked["linked_alert_id"] = alert.alert_id
                linked["alert_delivered_before_correction"] = alert.delivered
                alert.amendments.append(linked)
                affected.append({
                    "alert_id": alert.alert_id,
                    "count": alert.count,
                    "triggered": alert.triggered,
                    "delivered": alert.delivered,
                    "delivery_state": alert.delivery_state,
                    "amendment_delivered": False,
                })

            outcome = {
                "ok": True,
                "duplicate": False,
                "correction_id": correction_id,
                "amendment": (
                    dict(alert.amendments[-1]) if affected and alert.amendments
                    else amendment
                ),
                "affected_alerts": affected,
                "recounted_event_keys": [event.key],
                "recounted_sources": [source_id],
                "other_sources_recounted": False,
                "event": event.to_dict(),
            }
            self._corrections[correction_id] = dict(outcome)
            return outcome

    def _find_event(
        self, source_id: str, record_id: str, line_number: int | None,
    ) -> LoginEvent | None:
        if record_id:
            return self.events.get(event_key(source_id, line_number or 0, record_id))
        if line_number is not None:
            matches = [
                event for event in self.events.values()
                if event.source_id == source_id and event.line_number == line_number
            ]
            if len(matches) == 1:
                return matches[0]
            if matches:
                # 同来源同批多个记录共用行号时，只取该原行本身（不跨来源、不猜）。
                return matches[0]
        return None

    # ----- 交付 -----

    def deliver(
        self,
        alert_id: str,
        *,
        target: str,
        target_ack: bool = True,
        verification_ack: bool = False,
    ) -> dict[str, Any]:
        """向告警目标交付一次告警；字段核验端未确认时保留“已送达待确认”。

        关键：``alert_sent`` 与 ``delivered`` 不因确认缺失而回退，
        恢复时不能把“确认未达”当成“告警未发”重新计数。
        """
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                return {"ok": False, "message": "告警不存在"}
            alert.delivered = True
            alert.delivered_target = target
            alert.acked_endpoints = {
                target: bool(target_ack),
                "field_verifier": bool(verification_ack),
            }
            if target_ack and verification_ack:
                alert.delivery_state = "已送达已确认"
                alert.interruption = {}
            elif target_ack:
                alert.delivery_state = "已送达待确认"
                alert.interruption = {
                    "interrupted": True,
                    "reason": "字段核验端未收到交付确认",
                    "target_received": True,
                    "alert_sent": True,
                    "verification_ack": False,
                }
            else:
                alert.delivery_state = "未送达"
                alert.delivered = False
                alert.interruption = {
                    "interrupted": True,
                    "reason": "告警目标未确认接收",
                    "target_received": False,
                    "alert_sent": False,
                    "verification_ack": bool(verification_ack),
                }
            return {
                "ok": True,
                "alert_id": alert.alert_id,
                "alert_sent": alert.delivered,
                "delivered": alert.delivered,
                "delivery_state": alert.delivery_state,
                "interruption": dict(alert.interruption),
                "recounted": False,
            }

    def acknowledge(self, alert_id: str, endpoint: str, ok: bool = True) -> dict[str, Any]:
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                return {"ok": False, "message": "告警不存在"}
            alert.acked_endpoints[endpoint] = bool(ok)
            if alert.interruption and endpoint == "field_verifier" and ok:
                alert.delivery_state = "已送达已确认"
                alert.interruption = {}
            return {
                "ok": True,
                "alert_id": alert_id,
                "delivery_state": alert.delivery_state,
                "acked_endpoints": dict(alert.acked_endpoints),
            }

    def resume_delivery(self, alert_id: str) -> dict[str, Any]:
        """中断后恢复：原告警不重发、不重新计数；应交付的修正必须交付。"""
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                return {"ok": False, "message": "告警不存在"}
            original = {
                "alert_id": alert.alert_id,
                "already_sent": alert.delivered,
                "retransmit": False,
                "recount": False,
                "resend": False,
                "delivery_state": alert.delivery_state,
                "count": alert.count,
                "count_preserved": True,
                "note": (
                    "原告警已送达，确认缺失不等于告警未发；保持原计数"
                    if alert.delivered else "原告警尚未送达，按未送达处理"
                ),
            }
            delivered_amendments: list[dict[str, Any]] = []
            skipped_amendments: list[dict[str, Any]] = []
            for amendment in alert.amendments:
                if amendment.get("delivered"):
                    skipped_amendments.append({
                        "correction_id": amendment.get("correction_id"),
                        "reason": "修正已交付，重放不重复交付",
                    })
                    continue
                amendment["delivered"] = True
                amendment["delivered_at"] = _now()
                amendment["linked_alert_id"] = alert.alert_id
                amendment["delivery_state"] = (
                    "已送达已确认"
                    if alert.acked_endpoints.get("field_verifier")
                    else "已送达待确认"
                )
                delivered_amendments.append({
                    "correction_id": amendment.get("correction_id"),
                    "linked_alert_id": alert.alert_id,
                    "basis": amendment.get("basis", {}),
                    "delivered": True,
                })
            return {
                "ok": True,
                "alert_id": alert.alert_id,
                "original": original,
                "amendments_delivered": delivered_amendments,
                "amendments_skipped": skipped_amendments,
                "recounted": False,
                "count": alert.count,
            }

    # ----- 交班确认 -----

    def confirm(self, alert_id: str) -> dict[str, Any]:
        """交班确认；同一告警跨线程/跨进程只允许确认一次。"""
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                return {"ok": False, "message": "告警不存在"}
            if alert.confirmed:
                return {
                    "ok": True,
                    "alert_id": alert_id,
                    "confirmed": True,
                    "duplicate": True,
                    "confirmed_version": alert.confirmed_version,
                    "count": alert.count,
                }
            marker = self._claim_confirmation(alert)
            if marker.get("already_confirmed"):
                alert.confirmed = True
                alert.confirmed_version = marker.get("confirmed_version") or alert.convention_version
                alert.confirmed_at = marker.get("confirmed_at") or _now()
                return {
                    "ok": True,
                    "alert_id": alert_id,
                    "confirmed": True,
                    "duplicate": True,
                    "confirmed_version": alert.confirmed_version,
                    "count": alert.count,
                }
            alert.confirmed = True
            alert.confirmed_version = alert.convention_version
            alert.confirmed_at = _now()
            self._write_confirmation(marker, {
                "alert_id": alert_id,
                "confirmed_version": alert.confirmed_version,
                "confirmed_at": alert.confirmed_at,
                "count": alert.count,
                "participating_rows": [row["raw_line"] for row in alert.evidence],
            })
            return {
                "ok": True,
                "alert_id": alert_id,
                "confirmed": True,
                "duplicate": False,
                "confirmed_version": alert.confirmed_version,
                "count": alert.count,
                "confirmed_at": alert.confirmed_at,
            }

    # ----- 审计与交班判定 -----

    def audit(self, alert_id: str, *, next_convention_version: str | None = None) -> dict[str, Any]:
        """核对实际参与告警的原行、字段版本、矛盾原值、复核清单和下一轮计数。"""
        with self._lock:
            alert = self.alerts.get(alert_id)
            if alert is None:
                return {"ok": False, "message": "告警不存在"}
            source_events = [
                event for event in self.events.values()
                if event.source_id == alert.source_id
            ]
            contradictions = [
                {
                    "record_id": event.record_id,
                    "line_number": event.line_number,
                    "raw_line": event.raw_line,
                    "field_values": dict(event.field_values),
                    "conflict_values": _conflict_values(event),
                }
                for event in source_events
                if event.verdict == CONFLICT or len(_distinct_actions(event)) > 1
            ]
            # 已更正的原行也要能回查更正前的两个矛盾原值。
            for amendment in alert.amendments:
                before = amendment.get("before") or {}
                before_conflict = [
                    obs for obs in before.get("observations", [])
                    if obs.get("raw_value")
                ]
                if len({obs.get("normalized") for obs in before_conflict
                        if obs.get("normalized")}) > 1:
                    contradictions.append({
                        "record_id": amendment.get("record_id"),
                        "line_number": amendment.get("line_number"),
                        "raw_line": amendment.get("raw_line"),
                        "field_values": before.get("field_values", {}),
                        "conflict_values": before_conflict,
                        "revised_by": amendment.get("correction_id"),
                        "revised_verdict": (amendment.get("after") or {}).get("verdict"),
                    })
            contradictions = _dedupe_contradictions(contradictions)
            pending_review = [
                {
                    "record_id": event.record_id,
                    "line_number": event.line_number,
                    "raw_line": event.raw_line,
                    "field_values": dict(event.field_values),
                    "verdict": event.verdict,
                    "reason": event.review_reason,
                }
                for event in source_events
                if event.verdict == UNKNOWN
            ]
            review_checklist: list[dict[str, Any]] = []
            review_checklist.extend(
                {"item": "矛盾原值待核对", **row} for row in contradictions
            )
            review_checklist.extend(
                {"item": "未登记动作待核对", **row} for row in pending_review
            )
            if alert.delivered and not alert.acked_endpoints.get("field_verifier"):
                review_checklist.append({
                    "item": "字段核验端交付确认缺失",
                    "alert_id": alert.alert_id,
                    "delivery_state": alert.delivery_state,
                    "alert_sent": alert.delivered,
                })
            for amendment in alert.amendments:
                if not amendment.get("delivered"):
                    review_checklist.append({
                        "item": "修正尚未交付",
                        "correction_id": amendment.get("correction_id"),
                        "linked_alert_id": alert.alert_id,
                    })
            if not alert.confirmed:
                review_checklist.append({
                    "item": "告警尚未交班确认",
                    "alert_id": alert.alert_id,
                })

            if next_convention_version:
                next_convention = self.registry.get(alert.source_id, next_convention_version)
                next_version = next_convention_version
            else:
                next_convention = self.registry.active(alert.source_id)
                next_version = (
                    next_convention.version if next_convention is not None else ""
                )
            next_round = self._count_under_convention(
                alert.source_id, next_convention, source_events,
            )
            historical = None
            if alert.confirmed or alert.delivered:
                # 已确认/已送达的告警按当时实际使用的字段版本重算；
                # 新版约定生效后也不能把原告警的参与原行换口径重算。
                historical_convention = self.registry.get(
                    alert.source_id, alert.confirmed_version or alert.convention_version,
                )
                historical = self._count_under_convention(
                    alert.source_id, historical_convention, source_events,
                    historical_caliber=True,
                    event_keys=alert.candidate_keys or alert.event_keys,
                )

            return {
                "ok": True,
                "alert_id": alert.alert_id,
                "source_id": alert.source_id,
                "triggered": alert.triggered,
                "count": alert.count,
                "threshold": alert.threshold,
                "field_version_used": alert.convention_version,
                "field_group_used": alert.field_group,
                "participating_rows": alert.evidence,
                "excluded_rows": alert.excluded,
                "contradictory_values": contradictions,
                "duplicate_raw_values": [
                    row for row in contradictions
                ],
                "review_checklist": review_checklist,
                "next_round": next_round,
                "historical_recompute": historical,
                "delivery": {
                    "delivered": alert.delivered,
                    "delivery_state": alert.delivery_state,
                    "acked_endpoints": dict(alert.acked_endpoints),
                    "interruption": dict(alert.interruption),
                },
                "confirmed": alert.confirmed,
                "confirmed_version": alert.confirmed_version,
                "amendments": alert.amendments,
            }

    def evaluate_handover(
        self,
        alert_id: str,
        *,
        new_convention_version: str | None = None,
    ) -> dict[str, Any]:
        """交班判定：本轮是否还能完成该来源的告警计算。

        结论分两层：
        * 已确认/已送达的告警可以按当时实际使用的历史口径重算；
        * 新约定只认其转换表中登记的动作，旧名字原行不能自动沿用，
          新约定下真实计数不足时不能凭空补足本轮告警。
        """
        audit = self.audit(alert_id, next_convention_version=new_convention_version)
        if not audit.get("ok"):
            return audit
        alert = self.alerts[alert_id]
        next_round = audit["next_round"]
        historical = audit["historical_recompute"]
        can_finish_historical = alert.confirmed or alert.delivered
        can_finish_new = next_round["count"] > alert.threshold
        if can_finish_historical and not can_finish_new:
            decision = (
                "本轮可按历史口径完成已确认/已送达告警的重算；"
                "新约定下有效登录原行不足门槛，不能沿用旧名字形成新告警，"
                "需下一轮按新约定采集 SIGN_IN 原行"
            )
        elif can_finish_historical and can_finish_new:
            decision = "本轮可完成历史口径重算，且新约定下真实计数同样达到门槛"
        elif not can_finish_historical and can_finish_new:
            decision = "本轮不能完成历史告警（未确认/未送达），但新约定下真实计数达到门槛"
        else:
            decision = (
                "本轮不能完成该来源的登录告警计算：既无已确认历史口径，"
                "新约定下有效计数也未达门槛"
            )
        excluded_sources = [
            row for row in audit["next_round"]["excluded"]
            if row.get("reason") == "非本来源"
        ]
        return {
            "ok": True,
            "alert_id": alert_id,
            "source_id": alert.source_id,
            "decision": decision,
            "can_complete_historical": can_finish_historical,
            "can_complete_new_round": can_finish_new,
            "can_complete_this_round": can_finish_historical or can_finish_new,
            "historical_version": alert.confirmed_version or alert.convention_version,
            "historical_recompute": historical,
            "new_round": next_round,
            "excluded_sources": excluded_sources,
            "excluded_conflicts": audit["contradictory_values"],
            "review_checklist": audit["review_checklist"],
        }

    # ----- 内部 -----

    def _count_under_convention(
        self,
        source_id: str,
        convention: SourceConvention | None,
        events: list[LoginEvent],
        *,
        historical_caliber: bool = False,
        event_keys: list[str] | None = None,
    ) -> dict[str, Any]:
        if event_keys is not None:
            allowed = set(event_keys)
            events = [event for event in events if event.key in allowed]
        counted: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        for event in events:
            if event.source_id != source_id:
                excluded.append(_excluded_row(event, "other_source", "非本来源"))
                continue
            result = classify_with_convention(convention, source_id, event.field_values)
            if result["verdict"] == LOGIN and result["effective"]:
                counted.append({
                    "record_id": event.record_id,
                    "line_number": event.line_number,
                    "raw_line": event.raw_line,
                    "field_values": dict(event.field_values),
                    "field_version": result["field_version"],
                    "verdict": result["verdict"],
                })
            else:
                excluded.append({
                    "record_id": event.record_id,
                    "line_number": event.line_number,
                    "raw_line": event.raw_line,
                    "field_values": dict(event.field_values),
                    "verdict": result["verdict"],
                    "reason": result["review_reason"],
                })
        return {
            "convention_version": convention.version if convention else "",
            "caliber": "historical" if historical_caliber else "next_round",
            "count": len(counted),
            "rows": counted,
            "excluded": excluded,
        }

    def _claim_confirmation(self, alert: LoginAlert) -> dict[str, Any]:
        """跨进程原子占位：O_EXCL 创建标记文件，只允许一个进程写入。"""
        os.makedirs(self._handover_dir, exist_ok=True)
        path = os.path.join(
            self._handover_dir, f"{_safe_id(alert.alert_id)}.confirm.json",
        )
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            try:
                with open(path, encoding="utf-8") as handle:
                    data = json.load(handle)
            except (OSError, json.JSONDecodeError):
                data = {}
            return {"already_confirmed": True, **data}
        else:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"alert_id": alert.alert_id, "claimed": True}, handle)
            return {"already_confirmed": False, "path": path}

    @staticmethod
    def _write_confirmation(marker: dict[str, Any], payload: dict[str, Any]) -> None:
        path = marker.get("path")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)


def _excluded_row(event: LoginEvent, reason: str, message: str) -> dict[str, Any]:
    return {
        "record_id": event.record_id,
        "source_id": event.source_id,
        "line_number": event.line_number,
        "raw_line": event.raw_line,
        "field_values": dict(event.field_values),
        "verdict": event.verdict,
        "reason": reason,
        "message": message,
        "review_reason": event.review_reason,
    }


def _exclusion_reason(event: LoginEvent) -> str:
    if event.verdict == CONFLICT:
        return "field_conflict"
    if event.verdict == UNKNOWN:
        return "pending_review"
    if event.verdict == LOGOUT:
        return "logout"
    if event.verdict == INACTIVE:
        return "inactive_convention"
    return "not_login"


def _exclusion_message(event: LoginEvent) -> str:
    messages = {
        "field_conflict": "双字段取值矛盾，不能计入",
        "pending_review": event.review_reason or "待核对动作",
        "logout": "登出动作不计入登录告警",
        "inactive_convention": event.review_reason,
        "not_login": event.review_reason or "非登录动作",
    }
    return messages[_exclusion_reason(event)]


def _distinct_actions(event: LoginEvent) -> set[str]:
    return {
        str(obs.get("normalized")) for obs in event.observations
        if obs.get("normalized")
    }


def _dedupe_contradictions(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        raw_values = sorted({
            str(item.get("raw_value")) for item in row.get("conflict_values", [])
        })
        marker = f"{row.get('source_id')}|{row.get('record_id')}|{row.get('line_number')}|{raw_values}|{row.get('revised_by', '')}"
        if marker in seen:
            continue
        seen.add(marker)
        result.append(row)
    return result


def _conflict_values(event: LoginEvent) -> list[dict[str, Any]]:
    """矛盾原值：保留每个动作字段的原值、规范化结果与是否来自换名。"""
    return [
        {
            "field": obs.get("field"),
            "canonical_field": obs.get("canonical_field"),
            "raw_value": obs.get("raw_value"),
            "normalized": obs.get("normalized"),
            "field_renamed": obs.get("field_renamed", False),
            "conversion_evidence": obs.get("conversion_evidence", ""),
            "pending_reason": obs.get("pending_reason", ""),
        }
        for obs in event.observations
    ]


# ---------- 便于外部构造的工厂 ----------


def make_convention(
    *,
    source_id: str,
    version: str,
    fields: list[str],
    conversions: list[dict[str, Any]],
    state: str = "生效中",
    renames: dict[str, str] | None = None,
    group_id: str = "login.action",
    description: str = "",
) -> SourceConvention:
    """用扁平参数构造来源约定，测试和接口导入共用。"""
    return SourceConvention(
        source_id=source_id,
        version=version,
        state=state,
        groups=[LoginFieldGroup(group_id=group_id, fields=tuple(fields))],
        conversions=[
            ValueConversion(
                raw_value=str(item.get("raw_value") or ""),
                normalized=str(item.get("normalized") or "").upper(),
                evidence=str(item.get("evidence") or ""),
                field_name=str(item.get("field_name") or ""),
                note=str(item.get("note") or ""),
            )
            for item in conversions
        ],
        renames=dict(renames or {}),
        description=description,
    )


def make_engine(
    registry: LoginConventionRegistry | None = None,
    handover_dir: str | None = None,
) -> LoginAlertEngine:
    return LoginAlertEngine(registry=registry, handover_dir=handover_dir)
