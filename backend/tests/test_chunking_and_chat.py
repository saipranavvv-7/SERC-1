"""
Unit and integration tests for SERC Chunking Service,
Conversational SOC Chatbot, and Follow-Up Investigation Endpoints.
"""
import pytest
from backend.services.chunking_service import RecursiveCharacterTextSplitter, SecurityKnowledgeChunker
from backend.services.gpt_analysis_service import gpt_analysis_service
from backend.routes.alerts import (
    chat_with_copilot,
    reset_chat_session,
    ChatRequest,
    RECENT_ALERTS_CACHE,
    RECENT_PIXTRAL_CACHE,
    RECENT_EVIDENCE_CACHE,
)


@pytest.fixture
def sample_raw_record():
    return {
        "incident_id": "INC-TEST-001",
        "attack_type": "Brute Force",
        "incident_description": "Repeated unauthorized authentication attempts targeting root credentials on SSH port 22.",
        "detection_indicators": "Multiple PAM 5 failures from external IP 198.51.100.50 within 60 seconds.",
        "investigation_steps": "Inspect /var/log/auth.log; verify if any session was successfully established.",
        "containment_steps": "Drop packets from source IP via iptables; enforce fail2ban rate limits.",
        "recommended_response": "Block malicious IP at perimeter firewall; rotate root credentials.",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Password Guessing",
        "mitre_tactic": "Credential Access",
        "mitre_description": "Adversaries may systematically guess passwords to authenticate to remote accounts.",
        "mitre_detection": "Monitor for high volumes of failed logon events (Event ID 4625 or syslog auth failures).",
        "mitre_mitigations": "Account lockout policies; multi-factor authentication (M1036, M1032).",
        "nist_function": "DE (Detect)",
        "nist_category": "DE.CM (Continuous Monitoring)",
        "nist_subcategory": "DE.CM-01",
        "nist_description": "Networks and computing environments are monitored to detect anomalies.",
        "knowledge_set": "Combined Incident-MITRE-NIST",
        "source_type": "Synthetic Incident Corpus",
        "source_reference": "NIST CSF 2.0 / MITRE ATT&CK v14",
        "mapping_confidence": "0.95"
    }


@pytest.fixture
def sample_wazuh_alert():
    return {
        "id": "1790761522.100002",
        "timestamp": "2026-09-30T10:36:05.412+0000",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "sshd: SSH brute force attack detected (multiple failed logins)",
            "firedtimes": 18,
            "mitre": {
                "id": ["T1110.001"],
                "tactic": ["Credential Access"],
                "technique": ["Password Guessing"]
            }
        },
        "agent": {
            "id": "001",
            "name": "server-prod-01",
            "ip": "192.168.1.20"
        },
        "decoder": {"name": "sshd"},
        "full_log": "Sep 30 10:36:04 server-prod-01 sshd[18450]: PAM 5 more authentication failures; rhost=198.51.100.50 user=root",
        "data": {
            "srcip": "198.51.100.50",
            "dstport": "22",
            "srcuser": "root"
        }
    }


# ============================================================================
# 1. Chunking Implementation Tests
# ============================================================================

def test_recursive_splitter_basic():
    splitter = RecursiveCharacterTextSplitter(chunk_size=50, chunk_overlap=10)
    text = "Paragraph one with several words.\n\nParagraph two with additional details.\n\nParagraph three."
    chunks = splitter.split_text(text)
    assert len(chunks) >= 2
    for c in chunks:
        assert len(c) <= 65  # allows slight boundary slack


def test_chunker_generates_three_knowledge_sources(sample_raw_record):
    chunker = SecurityKnowledgeChunker(chunk_size=500, chunk_overlap=80)
    chunks = chunker.chunk_record(sample_raw_record)
    assert len(chunks) >= 3

    sources = {c["knowledge_source"] for c in chunks}
    assert "Incident Response Guidance" in sources
    assert "MITRE ATT&CK" in sources
    assert "NIST CSF 2.0" in sources


def test_chunker_preserves_metadata(sample_raw_record):
    chunker = SecurityKnowledgeChunker(chunk_size=500, chunk_overlap=80)
    chunks = chunker.chunk_record(sample_raw_record)

    for idx, c in enumerate(chunks):
        assert c["chunk_id"] == f"INC-TEST-001#chunk-{idx}"
        assert c["incident_id"] == "INC-TEST-001"
        assert c["attack_type"] == "Brute Force"
        assert c["mitre_technique_id"] == "T1110.001"
        assert c["mitre_technique_name"] == "Password Guessing"
        assert c["nist_function"] == "DE (Detect)"
        assert c["nist_category"] == "DE.CM (Continuous Monitoring)"
        assert len(c["search_text"]) > 10
        assert len(c["chunk_text"]) > 10


def test_chunker_handles_empty_fields_gracefully():
    chunker = SecurityKnowledgeChunker()
    minimal_record = {
        "incident_id": "INC-MINIMAL",
        "attack_type": "Generic Anomaly",
        "combined_knowledge_text": "Fallback text for security knowledge record without specific fields."
    }
    chunks = chunker.chunk_record(minimal_record)
    assert len(chunks) >= 1
    assert chunks[0]["incident_id"] == "INC-MINIMAL"


# ============================================================================
# 2. Conversational Chatbot Follow-Up Tests
# ============================================================================

def test_chat_turn_trigger_explanation(sample_wazuh_alert):
    pixtral_info = {"summary": "SSH brute force attempts detected.", "observable_indicators": {"source_ip": "198.51.100.50"}}
    evidence = [{"incident_id": "INC-001", "knowledge_source": "Incident Response Guidance"}]

    resp = gpt_analysis_service.chat_turn(
        alert=sample_wazuh_alert,
        pixtral_info=pixtral_info,
        evidence=evidence,
        message="Why was this alert triggered?"
    )

    assert "reply" in resp
    assert "5712" in resp["reply"] or "SSH" in resp["reply"]
    assert "suggested_prompts" in resp
    assert len(resp["suggested_prompts"]) > 0


def test_chat_turn_mitre_explanation(sample_wazuh_alert):
    pixtral_info = {"observable_indicators": {}}
    evidence = [{"mitre_technique_id": "T1110.001", "mitre_technique_name": "Password Guessing"}]

    resp = gpt_analysis_service.chat_turn(
        alert=sample_wazuh_alert,
        pixtral_info=pixtral_info,
        evidence=evidence,
        message="Can you explain this MITRE ATT&CK technique?"
    )

    assert "T1110" in resp["reply"]
    assert "Mitigations" in resp["reply"] or "M1036" in resp["reply"]


def test_chat_turn_severity_assessment(sample_wazuh_alert):
    pixtral_info = {"observable_indicators": {}}
    resp = gpt_analysis_service.chat_turn(
        alert=sample_wazuh_alert,
        pixtral_info=pixtral_info,
        evidence=[],
        message="How serious is this security incident?"
    )
    assert "HIGH" in resp["reply"] or "CRITICAL" in resp["reply"] or "10" in resp["reply"]


def test_chat_turn_investigation_next_steps(sample_wazuh_alert):
    pixtral_info = {"observable_indicators": {"source_ip": "198.51.100.50"}}
    resp = gpt_analysis_service.chat_turn(
        alert=sample_wazuh_alert,
        pixtral_info=pixtral_info,
        evidence=[],
        message="What should I investigate next?"
    )
    assert "198.51.100.50" in resp["reply"]
    assert "server-prod-01" in resp["reply"]
    assert "Investigation" in resp["reply"] or "Playbook" in resp["reply"]


def test_chat_turn_simpler_terms(sample_wazuh_alert):
    pixtral_info = {"observable_indicators": {"source_ip": "198.51.100.50"}}
    resp = gpt_analysis_service.chat_turn(
        alert=sample_wazuh_alert,
        pixtral_info=pixtral_info,
        evidence=[],
        message="Explain the recommended response steps in simpler terms."
    )
    assert "plain" in resp["reply"].lower() or "simple" in resp["reply"].lower()


def test_chat_turn_empty_message(sample_wazuh_alert):
    resp = gpt_analysis_service.chat_turn(
        alert=sample_wazuh_alert,
        pixtral_info={},
        evidence=[],
        message=""
    )
    assert "Please enter a specific question" in resp["reply"]


# ============================================================================
# 3. FastAPI Route Integration Tests
# ============================================================================

def test_chat_endpoint_with_active_context(sample_wazuh_alert):
    alert_id = "1790761522.100002"
    RECENT_ALERTS_CACHE[alert_id] = sample_wazuh_alert
    RECENT_PIXTRAL_CACHE[alert_id] = {"summary": "SSH brute force detected", "observable_indicators": {"source_ip": "198.51.100.50"}}
    RECENT_EVIDENCE_CACHE[alert_id] = [{"incident_id": "INC-001", "chunk_id": "INC-001#chunk-0"}]

    req = ChatRequest(
        alert_id=alert_id,
        message="What does this alert indicate?",
        history=[]
    )

    res = chat_with_copilot(req)
    assert res["alert_id"] == alert_id
    assert "indicate" in res["reply"].lower() or "threat" in res["reply"].lower()
    assert len(res["suggested_prompts"]) > 0


def test_chat_endpoint_reset():
    alert_id = "1790761522.100002"
    RECENT_ALERTS_CACHE[alert_id] = {"id": alert_id}
    res = reset_chat_session({"alert_id": alert_id})
    assert res["status"] == "success"
    assert alert_id not in RECENT_ALERTS_CACHE
