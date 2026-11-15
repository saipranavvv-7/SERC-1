"""Test helper: a tiny in-memory knowledge base built with the REAL parsers (real CSF workbook,
MITRE/IRM structure from synthetic inputs). Stands in for Qdrant."""
import json, re, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.services import knowledge_sources as ks
from backend.services import evidence_validator as ev

def hit(rec, score):
    return {"incident_id": rec["incident_id"], "chunk_id": rec["chunk_id"], "knowledge_source": rec["knowledge_source"],
            "section": rec["section"], "similarity_score": score, "low_confidence": score < 0.5,
            "attack_type": rec["attack_type"], "incident_description": rec["incident_description"],
            "mitre_tactic": rec["mitre_tactic"], "mitre_technique_id": rec["mitre_technique_id"],
            "mitre_technique_name": rec["mitre_technique_name"], "mitre_description": rec["mitre_description"],
            "mitre_mitigations": rec["mitre_mitigations"], "nist_function": rec["nist_function"],
            "nist_category": rec["nist_category"], "nist_subcategory": rec["nist_subcategory"],
            "source_title": rec["source_title"], "data_origin": rec["data_origin"],
            "source_reference": rec["source_reference"], "chunk_text": rec["chunk_text"], "snippet": rec["chunk_text"][:350]}

def build_records():
    recs = ks.load_nist_csf(ROOT / "data_sources" / "csf2.xlsx")
    bundle = {"type": "bundle", "objects": [
      {"type":"attack-pattern","id":"attack-pattern--a","name":"Password Guessing","description":"Adversaries with no prior knowledge of legitimate credentials may systematically guess passwords using a repetitive or iterative mechanism. Password guessing may or may not take into account the target's policies on password complexity.",
       "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"credential-access"}],
       "external_references":[{"source_name":"mitre-attack","external_id":"T1110.001","url":"https://attack.mitre.org/techniques/T1110/001"}]},
      {"type":"attack-pattern","id":"attack-pattern--b","name":"Brute Force","description":"Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
       "kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"credential-access"}],
       "external_references":[{"source_name":"mitre-attack","external_id":"T1110","url":"https://attack.mitre.org/techniques/T1110"}]},
      {"type":"course-of-action","id":"course-of-action--m1","name":"Account Use Policies","description":"x"},
      {"type":"course-of-action","id":"course-of-action--m2","name":"Multi-factor Authentication","description":"x"},
      {"type":"relationship","id":"relationship--1","relationship_type":"mitigates","source_ref":"course-of-action--m1","target_ref":"attack-pattern--a","description":"Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed."},
      {"type":"relationship","id":"relationship--2","relationship_type":"mitigates","source_ref":"course-of-action--m2","target_ref":"attack-pattern--a","description":"Use multi-factor authentication to reduce the effectiveness of password guessing attacks."},
    ]}
    mini = Path(tempfile.mkdtemp()) / "mini-attack.json"
    mini.write_text(json.dumps(bundle), encoding="utf-8")
    recs += ks.load_mitre(mini)
    filler = " Additional background sentence about the process, tooling and reporting for the response team."
    pages = [
      "IRM #3 Unix/Linux Intrusion\nTLP:CLEAR\nAbstract\nHandle intrusions on Unix and Linux hosts." + filler * 3 + "\n1. Preparation\nMaintain an up to date inventory of systems and keep logs centralised for analysis." + filler * 4 + "\nTLP:CLEAR",
      "IRM #3 Unix/Linux Intrusion\nTLP:CLEAR\n2. Identification\nReview authentication logs for repeated failed logins from the same source address. Check for successful logins that follow a series of failures. Collect the list of accounts targeted during the activity." + filler * 3 + "\nTLP:CLEAR",
      "IRM #3 Unix/Linux Intrusion\nTLP:CLEAR\n3. Containment\nBlock the offending source address at the firewall once the analyst has confirmed the activity. Disable or reset the targeted accounts if there are signs of a successful login. Preserve logs and memory before changing the system." + filler * 3 + "\nTLP:CLEAR",
      "IRM #3 Unix/Linux Intrusion\nTLP:CLEAR\n4. Remediation\nReset credentials for affected accounts and enforce multi-factor authentication for remote access." + filler * 3 + "\n5. Recovery\nRestore normal access and monitor the accounts closely for repeated attempts after the reset." + filler * 3 + "\nTLP:CLEAR",
      "IRM #3 Unix/Linux Intrusion\nTLP:CLEAR\n6. Aftermath\nDocument the incident and update the playbooks with lessons learned." + filler * 4 + "\nTLP:CLEAR",
    ]
    for n, (sec, page, text) in enumerate(ks.chunk_pages(pages, detect_sections=True)):
        recs.append(ks._new_record(knowledge_source="incident_response", section=sec, chunk_id=f"IRM-3#{n:03d}", incident_id="IRM-3",
            attack_type="IRM-3 Unix/Linux Intrusion", source_title="CERT Societe Generale IRM", data_origin="official",
            source_reference=f"IRM-3 Unix/Linux Intrusion, p.{page}, {sec}", chunk_text=f"IRM-3 Unix/Linux Intrusion ({sec}):\n{text}"))
    return ks.dedupe(recs)

class FakeRetriever:
    def __init__(self, recs): self.recs = recs
    def search(self, query, top_k=5):
        q = ev.tokens(query); scored = []
        for r in self.recs:
            t = ev.tokens(r["chunk_text"]); ov = len(q & t) / (len(q) or 1)
            scored.append((min(0.75, 0.30 + ov), r))
        scored.sort(key=lambda x: -x[0])
        out, per = [], {}
        for sc, r in scored:                      # a source-balanced top-k, like the real retriever
            per.setdefault(r["knowledge_source"], 0)
            if per[r["knowledge_source"]] < 2: out.append(hit(r, round(sc, 4))); per[r["knowledge_source"]] += 1
            if len(out) >= top_k: break
        return out
    def lookup_technique(self, tid):
        return [hit(r, 1.0) for r in self.recs if r["mitre_technique_id"] == tid]
