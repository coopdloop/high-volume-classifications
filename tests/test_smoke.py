"""Offline smoke tests: routing policy, store round-trip, guardrail plumbing.

No Loki/OpenRouter/Phoenix needed — store tests use a tmp SQLite DB and
noul_gate is exercised with a stub classifier.
"""

import os
import time

import pytest
import yaml

from soc import store
from soc.classify import decide, noul_confidence
from soc.jev_client import Classification, OpenRouterBackend, get_classifier, noul_gate
from soc.questions import question_set


def make_classification(is_suspicious=0.95, severity=4.0, tactic="execution"):
    return Classification(
        nouls={"is_suspicious": is_suspicious, "needs_context": 0.1},
        choices={"mitre_tactic": {"choice": tactic, "confidence": 0.9}},
        scores={"severity": {"score": severity, "confidence": 0.8}},
    )


def test_noul_confidence():
    assert noul_confidence(0.5) == 0.0   # maximally uncertain
    assert noul_confidence(0.0) == 1.0
    assert noul_confidence(0.9) == pytest.approx(0.8)


def test_decide_against_real_policy():
    """Route fabricated classifications through the actual thresholds.yml."""
    with open("config/thresholds.yml") as f:
        policy = yaml.safe_load(f)
    assert decide(make_classification(is_suspicious=0.95), 3, policy) == "escalate"
    # confident, low severity, low suspicion -> benign
    assert decide(make_classification(is_suspicious=0.1, severity=1.0, tactic="benign"), 1, policy) == "benign"
    # p near 0.5 -> low confidence -> safe default is escalate
    assert decide(make_classification(is_suspicious=0.5, severity=1.0), 1, policy) == "escalate"
    # suspicious but confident enough and below every escalate rule -> review
    assert decide(make_classification(is_suspicious=0.8, severity=2.0), 1, policy) == "review"


@pytest.fixture()
def tmp_db(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "test.db"))
    store.init()
    return store


def test_store_roundtrip(tmp_db):
    eid = tmp_db.insert_event({
        "ts": time.time(), "source": "sysmon", "host": "web1", "user": "alice",
        "raw": {"msg": "encoded powershell"}, "is_suspicious": 0.95,
        "suspicious_confidence": 0.9, "severity": 4.0, "severity_confidence": 0.8,
        "tactic": "execution", "tactic_confidence": 0.9, "needs_context": 0.1,
        "decision": "escalate", "backend": "test",
    })
    assert tmp_db.escalation_count("web1", None, 3600) == 1
    assert tmp_db.escalation_count("other", None, 3600) == 0
    assert [r["id"] for r in tmp_db.escalations_since(0, 3600)] == [eid]

    cid = tmp_db.upsert_campaign({"anchor": "web1", "hosts": ["web1"], "users": ["alice"],
                                  "tactics": ["execution"], "event_ids": [eid]})
    assert tmp_db.find_open_campaign("web1")["id"] == cid
    assert tmp_db.find_open_campaign("nope") is None

    aid = tmp_db.insert_approval(cid, {"action": "isolate host", "risk": "high", "reason": "r"})
    row = tmp_db.query("SELECT status, disruptive_prob FROM approvals WHERE id=?", (aid,))[0]
    assert row["status"] == "pending"


class StubClassifier:
    name = "stub"
    model = "stub-1"

    def noul(self, state, instructions):
        return 0.42, {"model": self.model, "cost": 0.001, "raw": {"gate": 0.42}}


def test_noul_gate_passthrough():
    rec = {}
    prob = noul_gate(StubClassifier(), "state", "disruptive?", record=rec)
    assert prob == 0.42
    assert rec["backend"] == "stub"
    assert rec["model"] == "stub-1"
    assert rec["cost"] == 0.001
    assert rec["raw"] == {"gate": 0.42}
    assert rec["latency_ms"] >= 0


def test_emulated_json_fence_parsing():
    assert OpenRouterBackend._parse('```json\n{"a": 1}\n```') == {"a": 1}
    assert OpenRouterBackend._parse('{"a": 1}') == {"a": 1}


def test_question_set_shape():
    qs = question_set()
    assert qs["is_suspicious"]["type"] == "noul"
    assert "benign" in qs["mitre_tactic"]["criteria"]
    assert len(qs["severity"]["criteria"]) == 5


def test_calibration_bins():
    from soc.api import _calibration_bins
    pairs = [(0.0, 0), (1.0, 1), (0.5, 1), (0.5, 0)]
    r = _calibration_bins(pairs, 2)
    assert r["events"] == 4
    assert r["positives"] == 2
    assert r["brier"] == pytest.approx((0 + 0 + 0.25 + 0.25) / 4)
    assert r["base_rate"] == 0.5
    assert r["skill"] == pytest.approx(1 - 0.125 / 0.25)
    assert [b["n"] for b in r["bins"]] == [1, 3]


def test_policy_hot_reload(tmp_path, monkeypatch):
    from soc import policy
    monkeypatch.setattr(policy, "_cache", None)
    f = tmp_path / "thresholds.yml"
    f.write_text("window_minutes: 20\n")
    monkeypatch.setenv("THRESHOLDS", str(f))
    assert policy.load()["window_minutes"] == 20
    os.utime(f, (time.time() + 5, time.time() + 5))  # same content, new mtime
    assert policy.load()["window_minutes"] == 20
    f.write_text("window_minutes: 99\n")
    os.utime(f, (time.time() + 10, time.time() + 10))
    assert policy.load()["window_minutes"] == 99
    f.unlink()  # deleted file keeps last good policy
    assert policy.load()["window_minutes"] == 99


def test_get_classifier_requires_key(monkeypatch):
    monkeypatch.setenv("SYSTEM1_BACKEND", "emulated")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        get_classifier()
