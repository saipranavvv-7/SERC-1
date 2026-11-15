"""
Evidence-Backed Response Validator.

Every statement SERC makes becomes a CLAIM. Each claim is checked with deterministic rules:

  observed_fact   must be literally present in the alert fields.
  interpretation  MITRE mappings must be declared by the Wazuh rule (or confirmed by a retrieved record).
  recommendation  must be grounded in the evidence record it cites (word overlap), and that record
                  must actually be relevant to the alert (similarity score).

  Rules applied to all claims: unknown IP addresses, severity out of proportion, "is compromised"
  declarations, and citations of evidence that was never retrieved.

What this does NOT do: it does not prove that advice is correct or safe for your environment. It shows
whether a statement is traceable to the alert or to a cited source. A person still decides.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional

SUPPORTED = "Supported"
PARTIAL = "Partially Supported"
CONFLICT = "Conflicting Evidence"
INSUFFICIENT = "Insufficient Evidence"
REVIEW = "Requires Review"
STATUSES = [SUPPORTED, PARTIAL, CONFLICT, INSUFFICIENT, REVIEW]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
CITE_RE = re.compile(r"\bE(\d{1,2})\b")
COMPROMISE_RE = re.compile(
    r"\b(?:is|are|was|were|has been|have been)\s+(?:now\s+|successfully\s+|already\s+)?(?:compromised|breached)\b"
    r"|\b(?:attack|breach|intrusion)\s+(?:was\s+|has\s+been\s+)?(?:successful|confirmed)\b"
    r"|\bconfirmed\s+(?:breach|compromise|intrusion)\b",
    re.I,
)
# Severity words only count when they describe THIS event ("a critical breach"), not generic guidance ("critical assets").
EVENT_SEVERITY_RE = re.compile(
    r"\b(?:this|the|an?)\s+(?:\w+\s+){0,3}?(?:incident|alert|event|attack|breach|intrusion|activity|compromise)\b[^.;]{0,60}\b(?:critical|emergency|severe|catastrophic)\b"
    r"|\b(?:critical|emergency|severe|catastrophic)\s+(?:\w+\s+){0,2}(?:incident|alert|event|attack|breach|intrusion)\b", re.I)
# "if the account is compromised" is a condition in guidance, not a declaration that it happened.
HYPOTHETICAL_RE = re.compile(
    r"\b(?:if|when|whether|once|unless|in case|in the event|suspected|suspect|potentially|possibly|may|might|could|should)\b[^.;]{0,120}$", re.I)
DISMISS_RE = re.compile(r"\b(?:no action (?:is )?(?:needed|required)|false positive|benign|can be ignored)\b", re.I)
DESTRUCTIVE_RE = re.compile(
    r"\b(?:isolate|disable|quarantine|block|shut ?down|wipe|re-?image|rebuild|reset|revoke|delete|terminate|kill)\b", re.I)

_STOP = set(
    "the a an of to and or in on for with by is are be as at from that this it its into than then also may can "
    "should must will use using used any all each such these those their there which when where what who how if not "
    "have has had been being was were your you we our they them other more most some one two per via".split()
)
GROUND_STRONG = 0.60
GROUND_PARTIAL = 0.30


def declares_compromise(text: str) -> bool:
    for m in COMPROMISE_RE.finditer(text or ""):
        if HYPOTHETICAL_RE.search(text[max(0, m.start() - 130): m.start()]):
            continue
        return True
    return False


def short_ref(ref: str) -> str:
    """Drop a trailing '(https://...)' from a source reference for readable messages."""
    return re.sub(r"\s*\(https?://[^)]*\)", "", ref or "").strip()


def needs_approval(text: str) -> bool:
    """True when a recommendation opens with a disruptive action (isolate, disable, block, reset ...)."""
    return bool(DESTRUCTIVE_RE.search((text or "")[:70]))


def _stem(tok: str) -> str:
    for suf in ("ing", "ed", "es", "s"):
        if len(tok) > 4 and tok.endswith(suf):
            return tok[: -len(suf)]
    return tok


def tokens(text: str) -> set:
    raw = re.findall(r"[a-z0-9][a-z0-9\-\.]{2,}", (text or "").lower())
    return {_stem(t.strip(".-")) for t in raw if t.strip(".-") and t not in _STOP}


def grounding_score(claim_text: str, evidence_texts: List[str]) -> float:
    """Share of the claim's content words that appear in the cited evidence."""
    claim = tokens(claim_text)
    if not claim:
        return 0.0
    ev = tokens(" ".join(evidence_texts))
    return len(claim & ev) / len(claim)


def _result(claim: Dict[str, Any], idx: int, status: str, why: str, next_step: str, score: Optional[float] = None) -> Dict[str, Any]:
    return {
        "id": f"CLM-{idx:03d}",
        "type": claim["type"],
        "text": claim["text"],
        "status": status,
        "justification": why,
        "source": claim.get("source", ""),
        "evidence_ids": claim.get("evidence_ids", []),
        "next_step": next_step,
        "approval_required": bool(claim.get("approval_required")),
        "grounding": None if score is None else round(score, 2),
    }


def validate_claims(
    claims: List[Dict[str, Any]],
    view: Dict[str, Any],
    alert_text: str,
    evidence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    by_eid = {e["eid"]: e for e in evidence}
    evidence_text_all = " ".join(e.get("chunk_text", "") for e in evidence)
    declared_ids = set(view.get("mitre_ids", []))
    evidence_tech_ids = {e.get("mitre_technique_id") for e in evidence if e.get("mitre_technique_id")}
    mitre_confirmed_by_wazuh = view.get("mitre_source") == "wazuh_rule"
    level = view.get("level")

    results: List[Dict[str, Any]] = []
    for i, claim in enumerate(claims, start=1):
        text = claim["text"]
        ctype = claim["type"]
        cited = claim.get("evidence_ids", [])

        # ---- observed facts: must literally appear in the alert
        if ctype == "observed_fact":
            missing = [x for x in claim.get("expect", []) if str(x) not in alert_text]
            if missing:
                results.append(_result(claim, i, CONFLICT,
                                       f"States {', '.join(map(str, missing))}, which is not in the alert.",
                                       "Do not rely on this statement."))
            else:
                results.append(_result(claim, i, SUPPORTED,
                                       "Directly present in the alert fields.", "None. Read straight from alert telemetry."))
            continue

        # ---- rules that apply to every analysis claim
        unknown_ips = [ip for ip in IP_RE.findall(text) if ip not in alert_text and ip not in evidence_text_all]
        if unknown_ips:
            results.append(_result(claim, i, CONFLICT,
                                   f"Mentions IP address {unknown_ips[0]}, which is in neither the alert nor the retrieved evidence.",
                                   "Do not act on this statement until the address is explained."))
            continue
        if ctype == "interpretation" and level is not None and level <= 4 and EVENT_SEVERITY_RE.search(text):
            results.append(_result(claim, i, CONFLICT,
                                   f"Describes the event as critical or an emergency, but the alert level is only {level}.",
                                   "Check what supports this severity before escalating."))
            continue
        if ctype == "interpretation" and level is not None and level >= 8 and DISMISS_RE.search(text):
            results.append(_result(claim, i, REVIEW,
                                   f"Dismisses an alert at level {level}.", "A senior analyst should confirm before closing."))
            continue
        if declares_compromise(text):
            results.append(_result(claim, i, CONFLICT,
                                   "Declares a compromise or confirmed attack. An alert is a detection, not proof.",
                                   "Collect forensic evidence before making this claim."))
            continue
        bad_cites = [c for c in cited if c not in by_eid]
        if bad_cites:
            results.append(_result(claim, i, CONFLICT,
                                   f"Cites evidence {', '.join(bad_cites)} that was never retrieved.",
                                   "Discard the claim or find a real source."))
            continue

        # ---- interpretations: MITRE mappings
        if ctype == "interpretation":
            tech_ids = TECH_RE.findall(text)
            if claim.get("check") == "inferred_mapping":
                results.append(_result(claim, i, REVIEW,
                                       "The alert carries no MITRE mapping. This technique is an inference from retrieved text.",
                                       "Analyst to confirm the technique before relying on it."))
                continue
            if tech_ids:
                tid = tech_ids[0]
                parent = tid.split(".")[0]
                declared = tid in declared_ids or parent in declared_ids
                corroborated = tid in evidence_tech_ids or parent in {t.split(".")[0] for t in evidence_tech_ids}
                if declared and mitre_confirmed_by_wazuh:
                    extra = " and corroborated by a retrieved MITRE record" if corroborated else ""
                    results.append(_result(claim, i, SUPPORTED,
                                           f"{tid} is declared by the Wazuh rule{extra}.", "None."))
                elif declared:
                    results.append(_result(claim, i, REVIEW,
                                           f"{tid} was suggested by a text pattern, not by a Wazuh rule.",
                                           "Analyst to confirm the technique."))
                elif corroborated:
                    results.append(_result(claim, i, SUPPORTED, f"{tid} appears in a retrieved MITRE record.", "None."))
                else:
                    results.append(_result(claim, i, REVIEW,
                                           f"{tid} is neither in the alert nor in any retrieved record.",
                                           "Analyst to confirm the technique."))
                continue

        # ---- recommendations and other interpretations: grounded in the cited record?
        if not cited:
            results.append(_result(claim, i, INSUFFICIENT, "Cites no evidence.",
                                   "Find a supporting source or discard."))
            continue
        cited_items = [by_eid[c] for c in cited]
        score = grounding_score(text, [e.get("chunk_text", "") for e in cited_items])
        best_similarity = max(e.get("similarity_score", 0.0) for e in cited_items)
        weak_match = all(e.get("low_confidence") for e in cited_items)
        refs = ", ".join(f"{e['eid']} ({short_ref(e.get('source_reference') or e.get('source_title', ''))})" for e in cited_items)
        next_step = "Analyst to confirm this applies to this environment."
        if claim.get("approval_required") or needs_approval(text):
            next_step = "Needs analyst approval before anyone executes it."
        if score >= GROUND_STRONG and not weak_match:
            results.append(_result(claim, i, SUPPORTED,
                                   f"Taken from {refs}; {int(score * 100)}% of its wording is in that record.", next_step, score))
        elif score >= GROUND_STRONG and weak_match:
            results.append(_result(claim, i, PARTIAL,
                                   f"Matches {refs}, but that record is only a weak match for this alert (similarity {best_similarity:.2f}).",
                                   "Check whether the cited source really applies.", score))
        elif score >= GROUND_PARTIAL:
            results.append(_result(claim, i, PARTIAL,
                                   f"Only {int(score * 100)}% of the wording is found in {refs}.",
                                   "Read the cited source before acting.", score))
        else:
            results.append(_result(claim, i, INSUFFICIENT,
                                   f"Little of this wording ({int(score * 100)}%) is found in {refs}.",
                                   "Find a supporting source or discard.", score))

    return {"claims": results, "summary": summarize(results)}


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    facts = [r for r in results if r["type"] == "observed_fact"]
    analysis = [r for r in results if r["type"] != "observed_fact"]
    counts = Counter(r["status"] for r in analysis)
    fact_counts = Counter(r["status"] for r in facts)
    score = None
    if analysis:
        score = round(100 * (counts[SUPPORTED] + 0.5 * counts[PARTIAL]) / len(analysis))
    return {
        "facts_total": len(facts),
        "facts_supported": fact_counts[SUPPORTED],
        "analysis_total": len(analysis),
        "analysis_counts": {s: counts.get(s, 0) for s in STATUSES},
        "verification_score": score,
        "needs_attention": sum(1 for r in analysis if r["status"] != SUPPORTED),
    }
