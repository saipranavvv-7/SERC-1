"""
SERC tests. Run from the project root:   python -m pytest tests -v     (or: python tests/test_serc.py)
They use a small in-memory knowledge base built from your real csf2.xlsx, so no Qdrant or model is needed.
"""
import json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tests"))

from fake_kb import build_records, FakeRetriever
from backend.services import alert_parser as ap, analysis_service as an, evidence_validator as ev
from backend.services import knowledge_sources as ks

SAMPLES = json.loads((ROOT / "backend" / "data" / "sample_alerts.json").read_text(encoding="utf-8"))
_R = None
CSF = ROOT / "data_sources" / "csf2.xlsx"


def _need_csf():
    if not CSF.exists():
        raise unittest.SkipTest("data_sources/csf2.xlsx not found")


def retriever():
    _need_csf()
    global _R
    if _R is None:
        _R = FakeRetriever(build_records())
    return _R


def test_all_sample_alerts_are_valid():
    for a in SAMPLES:
        ok, errors, _ = ap.validate_alert(a)
        assert ok, errors
        assert ap.view_of(a)["description"]


def test_csf_workbook_parses_to_official_counts():
    _need_csf()
    recs = ks.load_nist_csf(ROOT / "data_sources" / "csf2.xlsx")
    sections = [r["section"] for r in recs]
    assert sections.count("function") == 6 and sections.count("category") == 22 and sections.count("subcategory") == 106
    assert not any("Withdrawn" in r["chunk_text"] for r in recs)


def test_raw_log_is_converted_and_flagged_as_heuristic():
    r = ap.parse_input("Sep 30 10:35:21 web01 sshd[1]: Failed password for root from 198.51.100.7 port 22 ssh2", "a.log")
    a = r["alert"]
    assert r["needs_confirmation"] and a["data"]["srcip"] == "198.51.100.7" and a["agent"]["name"] == "web01"
    assert a["_serc"]["mitre_source"] == "heuristic_pattern" and a["rule"]["level"] is None


def test_bad_inputs_are_handled():
    assert not ap.parse_input("   ")["ok"]
    assert ap.parse_input('{"rule": {"description": "x"')["source_type"] == "raw_text"
    assert not an.analyze_alert({"foo": 1}, retriever())["ok"]


def test_analysis_is_grounded_and_cited():
    out = an.analyze_alert(SAMPLES[0], retriever())
    assert out["ok"] and out["mode"] == "offline" and out["evidence"]
    ids = {e["eid"] for e in out["evidence"]}
    assert out["mitigation_steps"], "expected evidence-based mitigation steps"
    for s in out["investigation_steps"] + out["mitigation_steps"]:
        assert s["evidence_ids"] and set(s["evidence_ids"]) <= ids
    texts = [e["text"] for e in out["evidence"]]
    assert len(set(texts)) == len(texts), "retrieved evidence must not contain duplicate passages"


def test_missing_technique_and_empty_knowledge_base_do_not_crash():
    class Empty:
        def search(self, q, k=5): return []
        def lookup_technique(self, t): return []
    out = an.analyze_alert(SAMPLES[0], Empty())
    assert out["ok"] and any("knowledge base" in w for w in out["warnings"])


class HallucinatingLLM:
    text_live = True
    def complete_json(self, system, user):
        return json.dumps({
            "interpretations": [{"text": "The server is compromised and the attacker has full control.", "evidence": ["E1"]},
                                {"text": "The activity also looks like T1486 ransomware.", "evidence": ["E2"]}],
            "investigation_steps": [{"text": "Review logins from 203.0.113.99.", "evidence": ["E1"]},
                                    {"text": "Check for lateral movement using quantum analyzers.", "evidence": ["E9"]}],
            "mitigation_steps": [{"text": "Set account lockout policies after a number of failed login attempts.", "evidence": ["E2"]},
                                 {"text": "Purchase a new firewall appliance.", "evidence": ["E2"]},
                                 {"text": "Disable the admin account.", "evidence": []}]})


def test_validator_catches_hallucinated_claims():
    out = an.analyze_alert(SAMPLES[0], retriever(), llm=HallucinatingLLM())
    by_text = {c["text"]: c["status"] for c in out["claims"]}
    assert by_text["The server is compromised and the attacker has full control."] == ev.CONFLICT
    assert by_text["Review logins from 203.0.113.99."] == ev.CONFLICT           # IP not in alert or evidence
    assert by_text["Check for lateral movement using quantum analyzers."] == ev.CONFLICT  # cites E9, never retrieved
    assert by_text["The activity also looks like T1486 ransomware."] == ev.REVIEW
    assert by_text["Purchase a new firewall appliance."] == ev.INSUFFICIENT
    assert by_text["Disable the admin account."] == ev.INSUFFICIENT             # cites nothing
    assert by_text["Set account lockout policies after a number of failed login attempts."] == ev.SUPPORTED


def test_live_failure_falls_back_to_offline():
    class Broken:
        text_live = True
        def complete_json(self, s, u): raise TimeoutError("boom")
    out = an.analyze_alert(SAMPLES[0], retriever(), llm=Broken())
    assert out["mode"] == "offline" and any("live model" in w for w in out["warnings"])


def test_chat_refuses_to_guess_and_rejects_empty_question():
    assert not an.answer_question(SAMPLES[0], "  ", retriever())["ok"]
    out = an.answer_question(SAMPLES[0], "How do I stop password guessing on this account?", retriever())
    assert out["ok"] and out["citations"]


def test_feedback_keeps_one_decision_per_claim():
    import tempfile
    from backend.services.feedback_service import FeedbackService
    f = FeedbackService(Path(tempfile.mkdtemp()) / "fb.db")
    f.save("a", "CLM-001", "accepted"); f.save("a", "CLM-001", "rejected")
    rows = f.list_for_alert("a")
    assert len(rows) == 1 and rows[0]["decision"] == "rejected"


if __name__ == "__main__":
    n = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); n += 1; print("PASS", name)
            except unittest.SkipTest as why:
                print("SKIP", name, "-", why)
    print(f"\n{n} tests passed")
