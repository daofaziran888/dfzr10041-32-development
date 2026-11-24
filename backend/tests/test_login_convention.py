"""测试：访问日志登录动作换名、来源约定、带依据的登录告警与更正。

覆盖：
- 约定导入校验：转换表、依据、普通方法、同动作多原值
- 按来源分类：换名兼容、双字段矛盾、未登记动作
- 登录告警只计实际有效候选，依据可回查字段组与原行
- 更正：只重算该事件及影响告警；幂等；已送达告警留下修正依据
- 交付中断与恢复：确认未达 ≠ 告警未发；修正不得跳过
- 交班判定：历史口径重算、新约定真实计数、确认唯一
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.login_convention import (
    ACCESS, CONFLICT, INACTIVE, LOGIN, LOGOUT, UNKNOWN,
    LoginConventionRegistry, ValueConversion, LoginFieldGroup, SourceConvention,
    classify_with_convention, event_key, make_convention, make_engine,
)
from app.core.models import IngestJob, ParseRule
from app.core.pipeline import (
    IngestPipeline, PRESET_LOG_SOURCES, PRESET_PARSE_RULES,
)


# ---------- 约定工厂 ----------

def src_a_convention(version: str = "v1", source_id: str = "SRC-JIA") -> SourceConvention:
    """甲来源：action 与 verb 两个字段都承载动作，LOGIN 与 SIGN_IN 都算登录。"""
    return make_convention(
        source_id=source_id,
        version=version,
        fields=["action", "verb"],
        conversions=[
            {"raw_value": "SIGN_IN", "normalized": LOGIN, "evidence": "甲方接入文档 rev3"},
            {"raw_value": "LOGIN", "normalized": LOGIN, "evidence": "旧访问日志样例 line 12"},
            {"raw_value": "LOGOUT", "normalized": LOGOUT, "evidence": "甲方接入文档 rev3"},
            {"raw_value": "GET", "normalized": ACCESS, "evidence": "HTTP 方法语义"},
            {"raw_value": "POST", "normalized": ACCESS, "evidence": "HTTP 方法语义"},
        ],
        renames={"action_name": "action"},
    )


def src_a_new_convention(source_id: str = "SRC-JIA") -> SourceConvention:
    """甲来源新版约定：只认 SIGN_IN。"""
    return make_convention(
        source_id=source_id,
        version="v2",
        fields=["action"],
        conversions=[
            {"raw_value": "SIGN_IN", "normalized": LOGIN, "evidence": "甲方接入文档 rev4"},
            {"raw_value": "LOGOUT", "normalized": LOGOUT, "evidence": "甲方接入文档 rev4"},
        ],
    )


def src_yi_convention() -> SourceConvention:
    """乙来源：verb=LOGIN 只是访问标签，不是认证。"""
    return make_convention(
        source_id="SRC-YI",
        version="y1",
        fields=["verb"],
        conversions=[
            {"raw_value": "LOGIN", "normalized": ACCESS, "evidence": "乙来源字段说明：verb 仅为访问标签"},
            {"raw_value": "GET", "normalized": ACCESS, "evidence": "HTTP 方法语义"},
        ],
    )


def build_engine(handover_dir: str):
    registry = LoginConventionRegistry()
    assert registry.import_convention(src_a_convention())["ok"]
    assert registry.import_convention(src_yi_convention())["ok"]
    return make_engine(registry, handover_dir)


def feed(engine, rows):
    events = []
    for row in rows:
        events.append(engine.classify_entry(
            source_id=row["source_id"],
            line_number=row["line"],
            raw_line=row["raw"],
            fields=row["fields"],
        ))
    return events


# ---------- 导入校验 ----------

class TestConventionImport:
    def test_missing_evidence_sign_in_rejected(self):
        """缺少转换依据的 SIGN_IN 不能导入、也不能默认分类为 LOGIN。"""
        convention = make_convention(
            source_id="SRC-X", version="x1", fields=["action"],
            conversions=[{"raw_value": "SIGN_IN", "normalized": LOGIN, "evidence": ""}],
        )
        report = convention.validate()
        assert report["ok"] is False
        assert report["missing_evidence"][0]["raw_value"] == "SIGN_IN"
        registry = LoginConventionRegistry()
        assert registry.import_convention(convention)["registered"] is False
        # 即使绕过导入直接分类，缺依据的取值也只能留待核对。
        result = classify_with_convention(convention, "SRC-X", {"action": "SIGN_IN"})
        assert result["verdict"] != LOGIN

    def test_ordinary_method_cannot_be_renamed_to_login(self):
        """普通请求方法不能靠字段改名互换为 LOGIN/LOGOUT。"""
        convention = make_convention(
            source_id="SRC-X", version="x1", fields=["verb"],
            conversions=[{"raw_value": "GET", "normalized": LOGIN, "evidence": "误配"}],
        )
        report = convention.validate()
        assert report["ok"] is False
        assert report["ordinary_conflicts"][0]["raw_value"] == "GET"

    def test_two_raw_actions_same_target_traceable(self):
        """两个不同原动作配成同一动作时，可回查原值与转换依据。"""
        convention = src_a_convention()
        report = convention.validate()
        assert report["ok"] is True
        login_rows = report["collisions"][LOGIN]
        raw_values = {row["raw_value"] for row in login_rows}
        assert {"LOGIN", "SIGN_IN"} <= raw_values
        assert all(row["evidence"] for row in login_rows)
        warning = next(
            item for item in report["warnings"]
            if item["code"] == "shared_normalized_action" and item["normalized"] == LOGIN
        )
        assert set(warning["raw_values"]) == {"LOGIN", "SIGN_IN"}

    def test_field_rename_declared_and_checked(self):
        """换名声明落到规范字段；改名目标不在组内时给出警告。"""
        convention = make_convention(
            source_id="SRC-X", version="x1", fields=["action"],
            conversions=[{"raw_value": "LOGIN", "normalized": LOGIN, "evidence": "样例"}],
            renames={"action_name": "action"},
        )
        report = convention.validate()
        result = classify_with_convention(convention, "SRC-X", {"action_name": "LOGIN"})
        assert result["verdict"] == LOGIN
        assert result["observations"][0]["field"] == "action_name"
        assert result["observations"][0]["canonical_field"] == "action"
        assert result["observations"][0]["field_renamed"] is True
        assert report["warnings"] == []

        mistyped = make_convention(
            source_id="SRC-X", version="x2", fields=["action"],
            conversions=[{"raw_value": "LOGIN", "normalized": LOGIN, "evidence": "样例"}],
            renames={"action_name": "not_in_group"},
        )
        assert any(
            item["code"] == "rename_target_outside_group"
            for item in mistyped.validate()["warnings"]
        )


# ---------- 按来源分类 ----------

class TestSourceClassification:
    def test_same_value_different_source_meaning(self):
        """甲 action/verb 都是登录；乙 verb=LOGIN 只是访问标签。"""
        registry = LoginConventionRegistry()
        registry.import_convention(src_a_convention())
        registry.import_convention(src_yi_convention())
        jia_action = classify_with_convention(registry.active("SRC-JIA"), "SRC-JIA", {"action": "LOGIN"})
        jia_verb = classify_with_convention(registry.active("SRC-JIA"), "SRC-JIA", {"verb": "LOGIN"})
        yi_verb = classify_with_convention(registry.active("SRC-YI"), "SRC-YI", {"verb": "LOGIN"})
        assert jia_action["verdict"] == LOGIN and jia_action["effective"]
        assert jia_verb["verdict"] == LOGIN and jia_verb["effective"]
        assert yi_verb["verdict"] == ACCESS and not yi_verb["effective"]

    def test_conflicting_two_fields_not_counted(self):
        """甲 action=LOGIN 且 verb=GET：双字段矛盾，两个原值都要能回查。"""
        result = classify_with_convention(
            src_a_convention(), "SRC-JIA", {"action": "LOGIN", "verb": "GET"},
        )
        assert result["verdict"] == CONFLICT
        assert result["effective"] is False
        values = {obs["raw_value"] for obs in result["observations"]}
        assert {"LOGIN", "GET"} <= values

    def test_unregistered_action_waits_for_review(self):
        """未登记的新动作留待核对，不因字段名相同而参与告警。"""
        result = classify_with_convention(
            src_a_convention(), "SRC-JIA", {"action": "PASSWORD_RESET"},
        )
        assert result["verdict"] == UNKNOWN
        assert result["effective"] is False
        assert "留待核对" in result["review_reason"]

    def test_sign_in_and_new_action_separately(self):
        """单独送合法 SIGN_IN 与未登记动作：前者认证，后者待核。"""
        convention = src_a_convention()
        good = classify_with_convention(convention, "SRC-JIA", {"action": "SIGN_IN"})
        odd = classify_with_convention(convention, "SRC-JIA", {"action": "SIGN_IN_V2"})
        assert good["verdict"] == LOGIN and good["effective"]
        assert odd["verdict"] == UNKNOWN and not odd["effective"]

    def test_draft_convention_inactive(self):
        convention = make_convention(
            source_id="SRC-D", version="d1", state="草稿", fields=["action"],
            conversions=[{"raw_value": "SIGN_IN", "normalized": LOGIN, "evidence": "草稿依据"}],
        )
        result = classify_with_convention(convention, "SRC-D", {"action": "SIGN_IN"})
        assert result["verdict"] == INACTIVE
        assert result["effective"] is False


# ---------- 告警计数与依据 ----------

class TestLoginAlertCounting:
    def test_alert_counts_only_effective_and_explains(self):
        handover = tempfile.mkdtemp()
        engine = build_engine(handover)
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia line1 action=SIGN_IN", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia line2 verb=LOGIN", "fields": {"verb": "LOGIN"}},
            {"source_id": "SRC-JIA", "line": 3, "raw": "jia line3 action=LOGIN verb=GET", "fields": {"action": "LOGIN", "verb": "GET"}},
            {"source_id": "SRC-JIA", "line": 4, "raw": "jia line4 action=NEW", "fields": {"action": "NEW"}},
            {"source_id": "SRC-YI", "line": 1, "raw": "yi line1 verb=LOGIN", "fields": {"verb": "LOGIN"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=1)
        assert alert.count == 2
        assert alert.triggered is True
        assert alert.field_group == "login.action"
        rows = [item["raw_line"] for item in alert.evidence]
        assert rows == ["jia line1 action=SIGN_IN", "jia line2 verb=LOGIN"]
        reasons = {item["reason"] for item in alert.excluded}
        assert {"field_conflict", "pending_review", "other_source"} <= reasons
        # 值班员能查到是哪一组字段和原行触发。
        for item in alert.evidence:
            assert item["field_group"] == "login.action"
            assert item["field_version"] == "v1"
            assert item["observations"]

    def test_threshold_uses_effective_count(self):
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "line1", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "line2", "fields": {"action": "LOGIN", "verb": "GET"}},
            {"source_id": "SRC-JIA", "line": 3, "raw": "line3", "fields": {"action": "LOGIN", "verb": "GET"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=1)
        assert alert.count == 1
        assert alert.triggered is False


# ---------- 更正 ----------

class TestCorrection:
    def test_correction_recounts_only_its_source(self):
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1 SIGN_IN", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2 conflict", "fields": {"action": "LOGIN", "verb": "GET"}},
            {"source_id": "SRC-YI", "line": 1, "raw": "yi1 verb=LOGIN", "fields": {"verb": "LOGIN"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        assert alert.count == 1
        outcome = engine.correct(
            correction_id="COR-1", source_id="SRC-JIA", line_number=2,
            new_field_values={"verb": "POST"}, reason="值班员核对为普通访问",
        )
        assert outcome["ok"] is True
        assert outcome["other_sources_recounted"] is False
        assert outcome["recounted_sources"] == ["SRC-JIA"]
        assert outcome["affected_alerts"][0]["count"] == 1
        # 乙来源事件未被重算，也未进入甲告警。
        assert all("yi1" not in row["raw_line"] for row in alert.evidence)
        assert alert.event_keys == [event_key("SRC-JIA", 1, alert.evidence[0]["record_id"])]

    def test_correction_replay_is_idempotent(self):
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2", "fields": {"action": "LOGIN", "verb": "GET"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        first = engine.correct(correction_id="COR-2", source_id="SRC-JIA", line_number=2,
                               new_field_values={"verb": "POST"})
        replay = engine.correct(correction_id="COR-2", source_id="SRC-JIA", line_number=2,
                                new_field_values={"verb": "POST"})
        assert first["duplicate"] is False
        assert replay["duplicate"] is True
        assert len(alert.amendments) == 1

    def test_correction_can_add_effective_row(self):
        """把矛盾行更正为登录后，该告警按自身候选集合重算（不是全量扫描）。"""
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2", "fields": {"action": "LOGIN", "verb": "GET"}},
            {"source_id": "SRC-YI", "line": 1, "raw": "yi1", "fields": {"verb": "LOGIN"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        engine.correct(correction_id="COR-3", source_id="SRC-JIA", line_number=2,
                       new_field_values={"verb": "LOGOUT"})
        # verb=LOGOUT 与 action=LOGIN 矛盾 → 仍不计入。
        assert alert.count == 1
        engine.correct(correction_id="COR-4", source_id="SRC-JIA", line_number=2,
                       new_field_values={"verb": "LOGIN"})
        assert alert.count == 2
        assert len(alert.event_keys) == 2
        assert all("yi1" not in row["raw_line"] for row in alert.evidence)

    def test_correction_to_access_removes_row(self):
        """把只靠 action=LOGIN 成立的行更正成普通访问，告警按自身集合减一。"""
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2", "fields": {"action": "LOGIN"}},
            {"source_id": "SRC-YI", "line": 1, "raw": "yi1", "fields": {"verb": "LOGIN"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        assert alert.count == 2
        engine.correct(correction_id="COR-5", source_id="SRC-JIA", line_number=2,
                       new_field_values={"action": "POST"})
        assert alert.count == 1
        assert all("jia2" not in row["raw_line"] for row in alert.evidence)


# ---------- 交付中断与恢复 ----------

class TestDeliveryAndResume:
    def _interrupted_alert(self):
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1 SIGN_IN", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2 SIGN_IN", "fields": {"action": "SIGN_IN"}},
            {"source_id": "SRC-JIA", "line": 3, "raw": "jia3 conflict", "fields": {"action": "LOGIN", "verb": "GET"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=1)
        assert alert.count == 2 and alert.triggered
        engine.deliver(alert.alert_id, target="alert-receiver",
                       target_ack=True, verification_ack=False)
        return engine, alert

    def test_interruption_then_correction_then_resume(self):
        engine, alert = self._interrupted_alert()
        assert alert.delivery_state == "已送达待确认"
        assert alert.interruption["reason"] == "字段核验端未收到交付确认"

        correction = engine.correct(
            correction_id="COR-D1", source_id="SRC-JIA", line_number=3,
            new_field_values={"verb": "SIGN_IN"}, reason="核对为登录",
        )
        assert correction["affected_alerts"][0]["delivered"] is True
        assert alert.count == 3
        assert alert.amendments[0]["linked_alert_id"] == alert.alert_id
        assert alert.amendments[0]["record_id"] == alert.evidence[2]["record_id"]
        assert alert.amendments[0]["raw_line"] == "jia3 conflict"

        resumed = engine.resume_delivery(alert.alert_id)
        assert resumed["original"]["already_sent"] is True
        assert resumed["original"]["retransmit"] is False
        assert resumed["original"]["recount"] is False
        assert resumed["count"] == alert.count
        assert len(resumed["amendments_delivered"]) == 1
        assert resumed["amendments_delivered"][0]["linked_alert_id"] == alert.alert_id
        # 再恢复一次不会重复交付同一修正。
        again = engine.resume_delivery(alert.alert_id)
        assert again["amendments_delivered"] == []
        assert again["amendments_skipped"][0]["correction_id"] == "COR-D1"

    def test_verification_ack_clears_interruption(self):
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [{"source_id": "SRC-JIA", "line": 1, "raw": "r1", "fields": {"action": "SIGN_IN"}}])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        engine.deliver(alert.alert_id, target="alert-receiver", target_ack=True, verification_ack=False)
        assert alert.interruption
        engine.acknowledge(alert.alert_id, "field_verifier", ok=True)
        assert alert.interruption == {}
        assert alert.delivery_state == "已送达已确认"


# ---------- 交班 ----------

class TestHandover:
    def _setup_handover(self):
        """甲两条正常原行（action=LOGIN / verb=LOGIN）达到门槛；冲突行随后到达。"""
        handover = tempfile.mkdtemp()
        engine = build_engine(handover)
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1 action=LOGIN", "fields": {"action": "LOGIN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2 verb=LOGIN", "fields": {"verb": "LOGIN"}},
            {"source_id": "SRC-JIA", "line": 3, "raw": "jia3 action=LOGIN verb=GET", "fields": {"action": "LOGIN", "verb": "GET"}},
            {"source_id": "SRC-YI", "line": 1, "raw": "yi1 verb=LOGIN", "fields": {"verb": "LOGIN"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=1)
        assert alert.count == 2
        engine.deliver(alert.alert_id, target="alert-receiver")
        engine.confirm(alert.alert_id)
        return engine, alert

    def test_handover_new_convention_only_sign_in(self):
        engine, alert = self._setup_handover()
        registry = engine.registry
        assert registry.import_convention(src_a_new_convention())["ok"]
        decision = engine.evaluate_handover(alert.alert_id, new_convention_version="v2")
        assert decision["can_complete_historical"] is True
        assert decision["historical_recompute"]["count"] == 2
        assert decision["can_complete_new_round"] is False
        assert decision["new_round"]["count"] == 0
        assert decision["new_round"]["excluded"]
        assert "不能沿用旧名字" in decision["decision"]
        assert len(decision["review_checklist"]) >= 1

    def test_historical_recompute_excludes_yi_and_conflict(self):
        engine, alert = self._setup_handover()
        audit = engine.audit(alert.alert_id)
        assert audit["count"] == 2
        assert audit["field_version_used"] == "v1"
        assert audit["field_group_used"] == "login.action"
        assert len(audit["participating_rows"]) == 2
        contradictions = audit["contradictory_values"]
        assert len(contradictions) == 1
        assert contradictions[0]["line_number"] == 3
        conflict_raw = {row["raw_value"] for row in contradictions[0]["conflict_values"]}
        assert {"LOGIN", "GET"} <= conflict_raw
        historical = audit["historical_recompute"]
        assert historical["count"] == 2
        assert all("yi1" not in row["raw_line"] for row in historical["rows"])
        assert any("修正" in item["item"] or "确认" in item["item"] for item in audit["review_checklist"])

    def test_confirmation_only_once_across_processes(self):
        engine, alert = self._setup_handover()
        # 模拟另一个进程先占位：直接再建一个引擎，共享同一交班目录。
        other = make_engine(LoginConventionRegistry(), engine._handover_dir)
        other.registry.import_convention(src_a_convention())
        other.registry.import_convention(src_yi_convention())
        feed(other, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1 action=LOGIN", "fields": {"action": "LOGIN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2 verb=LOGIN", "fields": {"verb": "LOGIN"}},
        ])
        other_alert = other.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=1)
        # 同一 alert_id（来源+版本+阈值），标记文件已存在 → 只允许一次确认。
        assert other_alert.alert_id == alert.alert_id
        duplicate = other.confirm(other_alert.alert_id)
        assert duplicate["duplicate"] is True

    def test_unconfirmed_alert_cannot_recompute_historically(self):
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1", "fields": {"action": "LOGIN"}},
            {"source_id": "SRC-JIA", "line": 2, "raw": "jia2", "fields": {"verb": "LOGIN"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        engine.registry.import_convention(src_a_new_convention())
        decision = engine.evaluate_handover(alert.alert_id, new_convention_version="v2")
        assert decision["can_complete_historical"] is False
        assert decision["can_complete_this_round"] is False

    def test_existing_alert_does_not_mix_new_version_events(self):
        """新版约定到达后，既有告警仍按 v1 口径，不把 v2 事件混进去。"""
        engine = build_engine(tempfile.mkdtemp())
        feed(engine, [
            {"source_id": "SRC-JIA", "line": 1, "raw": "jia1", "fields": {"action": "LOGIN"}},
        ])
        alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        assert alert.count == 1 and alert.convention_version == "v1"
        engine.registry.import_convention(src_a_new_convention())
        assert engine.registry.active("SRC-JIA").version == "v2"
        engine.classify_entry(
            source_id="SRC-JIA", line_number=2, raw_line="jia2 SIGN_IN",
            fields={"action": "SIGN_IN"},
        )
        refreshed = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003",
                                 threshold=0, alert_id=alert.alert_id)
        assert refreshed.convention_version == "v1"
        assert refreshed.count == 1
        assert any(row["reason"] == "convention_version_mismatch" for row in refreshed.excluded)
        # 用新 alert_id（v2 口径）时可以正常计入 v2 事件，但 LOGIN 旧名字不再算。
        v2_alert = engine.check(source_id="SRC-JIA", event_type_id="EVEN-0003", threshold=0)
        assert v2_alert.convention_version == "v2"
        assert v2_alert.count == 1
        assert v2_alert.evidence[0]["raw_line"] == "jia2 SIGN_IN"

    def test_correction_on_confirmed_alert_uses_historical_version(self):
        """已确认告警收到更正仍按实际使用的历史口径，而不是当前新约定。"""
        engine, alert = self._setup_handover()
        engine.registry.import_convention(src_a_new_convention())
        outcome = engine.correct(
            correction_id="COR-HIST", source_id="SRC-JIA", line_number=3,
            new_field_values={"verb": "SIGN_IN"}, reason="按当时 v1 口径核对",
        )
        assert outcome["ok"] is True
        assert outcome["event"]["field_version"] == "v1"
        assert alert.count == 3


# ---------- 管道串联 ----------

class TestPipelineIntegration:
    def _make_entries(self, lines, source_key, rule_index):
        source = PRESET_LOG_SOURCES[source_key]
        pipeline = IngestPipeline(login_registry=LoginConventionRegistry())
        pipeline.login_registry.import_convention(
            src_a_convention(source_id=source.source_id),
        )
        rule = PRESET_PARSE_RULES[rule_index]
        entries = pipeline.parse_raw_lines(source, lines)
        return pipeline, pipeline.apply_parse_rules(entries, rule)

    def test_classify_events_uses_source_convention(self):
        """classify_events 按来源生效条件与换名兼容规则生成登录事件。"""
        line = 'Nov 15 14:30:07 auth-server sshd[8891]: SIGN_IN user=admin from=10.0.0.100'
        pipeline, parsed = self._make_entries([line], "sys-auth", 2)
        records = pipeline.classify_events(parsed)
        assert len(records) == 1
        record = records[0]
        assert record.login_verdict == LOGIN
        assert record.effective is True
        assert record.field_version == "v1"
        assert record.login_evidence["field_group"] == "login.action"
        assert record.login_evidence["observations"][0]["raw_value"] == "SIGN_IN"

    def test_check_anomaly_counts_effective_candidates(self):
        """check_anomaly 用实际有效候选计数，冲突/未登记不参与。"""
        lines = [
            'Nov 15 14:30:07 auth-server sshd[8891]: SIGN_IN user=admin from=10.0.0.1',
            'Nov 15 14:30:08 auth-server sshd[8892]: SIGN_IN user=bob from=10.0.0.2',
            'Nov 15 14:30:09 auth-server sshd[8893]: PASSWORD_RESET user=bad from=10.0.0.3',
        ]
        pipeline, parsed = self._make_entries(lines, "sys-auth", 2)
        records = pipeline.classify_events(parsed)
        assert [r.login_verdict for r in records] == [LOGIN, LOGIN, UNKNOWN]
        effective = pipeline.check_anomaly(records, "EVEN-0003", threshold=1)
        assert len(effective) == 2
        assert all(r.login_verdict == LOGIN for r in effective)
        assert all(r.parsed_fields.get("anomaly_alert") == "triggered" for r in effective)
        unregistered = [r for r in records if r.login_verdict == UNKNOWN][0]
        assert "anomaly_alert" not in unregistered.parsed_fields

    def test_check_anomaly_excludes_conflict(self):
        """双字段冲突即使事件类型是认证，也不能参与计数。"""
        pipeline, parsed = self._make_entries([
            'Nov 15 14:30:07 auth-server sshd[8891]: LOGIN user=a',
            'Nov 15 14:30:08 auth-server sshd[8892]: SIGN_IN user=b',
        ], "sys-auth", 2)
        parsed[0].parsed_fields["verb"] = "GET"
        parsed[1].parsed_fields["verb"] = "POST"
        records = pipeline.classify_events(parsed)
        assert [r.login_verdict for r in records] == [CONFLICT, CONFLICT]
        assert pipeline.check_anomaly(records, "EVEN-0003", threshold=0) == []

    def test_pipeline_correction_updates_record_only(self):
        lines = [
            'Nov 15 14:30:07 auth-server sshd[8891]: SIGN_IN user=admin from=10.0.0.1',
            'Nov 15 14:30:08 auth-server sshd[8892]: LOGIN user=bob from=10.0.0.2',
        ]
        pipeline, parsed = self._make_entries(lines, "sys-auth", 2)
        pipeline.login_engine = make_engine(pipeline.login_registry, tempfile.mkdtemp())
        records = pipeline.classify_events(parsed)
        assert [r.event_type.type_id for r in records] == ["EVEN-0003", "EVEN-0003"]
        alert = pipeline.login_engine.check(
            source_id=PRESET_LOG_SOURCES["sys-auth"].source_id,
            event_type_id="EVEN-0003", threshold=0,
        )
        assert alert.count == 2
        outcome = pipeline.apply_login_correction(
            correction_id="PIPE-1",
            source_id=PRESET_LOG_SOURCES["sys-auth"].source_id,
            line_number=2,
            new_field_values={"action": "PASSWORD_RESET"}, reason="改为未登记动作核对",
        )
        assert outcome["ok"] is True
        assert outcome["other_sources_recounted"] is False
        assert alert.count == 1
        corrected = [r for r in pipeline.get_login_records() if r.line_number == 2][0]
        assert corrected.login_verdict == UNKNOWN
        assert corrected.effective is False
        replay = pipeline.apply_login_correction(
            correction_id="PIPE-1",
            source_id=PRESET_LOG_SOURCES["sys-auth"].source_id,
            line_number=2,
            new_field_values={"action": "PASSWORD_RESET"}, reason="改为未登记动作核对",
        )
        assert replay["duplicate"] is True
        assert len(alert.amendments) == 1


if __name__ == "__main__":
    import traceback

    tests = []
    for cls in (TestConventionImport, TestSourceClassification, TestLoginAlertCounting,
                TestCorrection, TestDeliveryAndResume, TestHandover, TestPipelineIntegration):
        instance = cls()
        for name in dir(instance):
            if name.startswith("test_"):
                tests.append((f"{cls.__name__}.{name}", getattr(instance, name)))

    passed = failed = 0
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
            print(f"  PASS  test_login_convention: {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  test_login_convention: {name}")
            traceback.print_exc()
    print(f"\ntest_login_convention: {passed} passed, {failed} failed, {len(tests)} total")
    sys.exit(1 if failed else 0)
