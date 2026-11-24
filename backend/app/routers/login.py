"""登录来源约定接口：导入约定、核对转换表、分类日志、计告警与更正/交付。

所有固定路径都在通用 `/{module}` 路由之前注册，避免被动态路径吞掉。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.login_convention import (
    LoginAlertEngine, LoginConventionRegistry, convention_from_payload,
)

router = APIRouter(prefix="/api/login", tags=["登录来源约定"])

# 进程内单例：约定注册表保留历史版本，告警引擎保留原行/修正/交付依据。
registry = LoginConventionRegistry()
engine = LoginAlertEngine(registry=registry)


class ConventionPayload(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)


class ObservePayload(BaseModel):
    source_id: str
    entries: list[dict[str, Any]] = Field(default_factory=list)
    convention_version: str | None = None


class AlertCheckPayload(BaseModel):
    source_id: str
    event_type_id: str = "EVEN-0003"
    threshold: int = 0
    event_keys: list[str] | None = None
    alert_id: str | None = None


class CorrectionPayload(BaseModel):
    correction_id: str
    source_id: str
    new_field_values: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    record_id: str = ""
    line_number: int | None = None
    convention_version: str | None = None


class DeliverPayload(BaseModel):
    alert_id: str
    target: str = "alert-receiver"
    target_ack: bool = True
    verification_ack: bool = False


class AckPayload(BaseModel):
    endpoint: str = "field_verifier"
    ok: bool = True


def _require_alert(alert_id: str) -> None:
    if alert_id not in engine.alerts:
        raise HTTPException(status_code=404, detail=f"登录告警 {alert_id} 不存在")


@router.post("/conventions/validate")
def validate_convention(payload: ConventionPayload) -> dict[str, Any]:
    """只核对不导入：转换表、依据、普通方法冲突、同动作多原值。"""
    convention = convention_from_payload(payload.payload)
    return convention.validate()


@router.post("/conventions")
def import_convention(payload: ConventionPayload) -> dict[str, Any]:
    """导入来源约定；缺少转换依据或把普通方法配成登录动作时拒绝导入。"""
    report = registry.import_convention(convention_from_payload(payload.payload))
    return report


@router.get("/conventions")
def list_conventions() -> dict[str, Any]:
    return {"items": registry.all_versions()}


@router.get("/conventions/{source_id}")
def get_convention(source_id: str, version: str | None = None) -> dict[str, Any]:
    convention = registry.get(source_id, version)
    if convention is None:
        raise HTTPException(status_code=404, detail=f"来源 {source_id} 没有对应约定")
    return convention.snapshot()


@router.post("/events/classify")
def classify(payload: ObservePayload) -> dict[str, Any]:
    """按来源生效约定逐条判定，返回登录事件及依据。"""
    convention = registry.get(payload.source_id, payload.convention_version)
    events = []
    for index, entry in enumerate(payload.entries):
        fields = entry.get("fields") or {}
        event = engine.classify_entry(
            source_id=payload.source_id,
            line_number=int(entry.get("line_number") or index + 1),
            raw_line=str(entry.get("raw_line") or ""),
            fields=fields,
            record_id=str(entry.get("record_id") or ""),
            event_type_id=str(entry.get("event_type_id") or ""),
            convention=convention,
        )
        events.append(event.to_dict())
    return {"source_id": payload.source_id, "events": events}


@router.post("/alerts/check")
def check_alert(payload: AlertCheckPayload) -> dict[str, Any]:
    alert = engine.check(
        source_id=payload.source_id,
        event_type_id=payload.event_type_id,
        threshold=payload.threshold,
        event_keys=payload.event_keys,
        alert_id=payload.alert_id,
    )
    return alert.to_dict()


@router.get("/alerts")
def list_alerts(source_id: str | None = None) -> dict[str, Any]:
    items = [
        alert.to_dict(include_evidence=False) for alert in engine.alerts.values()
        if source_id is None or alert.source_id == source_id
    ]
    return {"items": items, "total": len(items)}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    _require_alert(alert_id)
    return engine.alerts[alert_id].to_dict()


@router.get("/alerts/{alert_id}/audit")
def audit_alert(alert_id: str, next_convention_version: str | None = None) -> dict[str, Any]:
    _require_alert(alert_id)
    return engine.audit(alert_id, next_convention_version=next_convention_version)


@router.get("/alerts/{alert_id}/handover")
def handover_alert(alert_id: str, new_convention_version: str | None = None) -> dict[str, Any]:
    _require_alert(alert_id)
    return engine.evaluate_handover(
        alert_id, new_convention_version=new_convention_version,
    )


@router.post("/corrections")
def correct(payload: CorrectionPayload) -> dict[str, Any]:
    """值班员更正原行动作值：只重算该事件及其告警；同一 correction_id 幂等。"""
    return engine.correct(
        correction_id=payload.correction_id,
        source_id=payload.source_id,
        new_field_values=payload.new_field_values,
        reason=payload.reason,
        record_id=payload.record_id,
        line_number=payload.line_number,
        convention_version=payload.convention_version,
    )


@router.post("/alerts/deliver")
def deliver(payload: DeliverPayload) -> dict[str, Any]:
    _require_alert(payload.alert_id)
    return engine.deliver(
        payload.alert_id,
        target=payload.target,
        target_ack=payload.target_ack,
        verification_ack=payload.verification_ack,
    )


@router.post("/alerts/{alert_id}/ack")
def acknowledge(alert_id: str, payload: AckPayload) -> dict[str, Any]:
    _require_alert(alert_id)
    return engine.acknowledge(alert_id, payload.endpoint, payload.ok)


@router.post("/alerts/{alert_id}/resume")
def resume(alert_id: str) -> dict[str, Any]:
    _require_alert(alert_id)
    return engine.resume_delivery(alert_id)


@router.post("/alerts/{alert_id}/confirm")
def confirm(alert_id: str) -> dict[str, Any]:
    _require_alert(alert_id)
    return engine.confirm(alert_id)
