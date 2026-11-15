"""
Source parsers for SERC's three knowledge collections.

    mitre              MITRE ATT&CK Enterprise      (STIX 2.1 JSON)
    nist               NIST CSF 2.0                 (reference-tool Excel export)
    incident_response  CERT-SG IRM playbooks and    (PDF)
                       NIST SP 800-61

This module only parses files. It needs no embedding model and no Qdrant, so it can be
checked with:  python backend/scripts/ingest_sources.py --dry-run

Every chunk keeps its provenance (source title, ID, page or section) so the UI can show
exactly where a piece of evidence came from.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("serc.knowledge_sources")
logging.getLogger("pypdf").setLevel(logging.ERROR)  # some PDFs trigger harmless parser warnings

SRC_MITRE = "mitre"
SRC_NIST = "nist"
SRC_IR = "incident_response"
ALL_SOURCES = (SRC_MITRE, SRC_NIST, SRC_IR)

# Used by --quick: a small, demo-friendly set (sub-techniques are included automatically).
QUICK_TECHNIQUES = {
    # Covers every technique used by the 55 sample alerts (sub-techniques are included automatically)
    "T1003", "T1021", "T1027", "T1046", "T1053", "T1055", "T1059", "T1070", "T1071", "T1078",
    "T1083", "T1091", "T1098", "T1110", "T1136", "T1190", "T1204", "T1485", "T1486", "T1505",
    "T1543", "T1547", "T1548", "T1556", "T1562", "T1566", "T1574", "T1595", "T1611",
}


# --------------------------------------------------------------------------- helpers
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML = re.compile(r"</?code>|<br\s*/?>")
_BULLET = re.compile(r"^[•▪·\-–*]\s")


def clean_text(text: Optional[str]) -> str:
    """Strip MITRE citation markers, markdown links and html tags."""
    if not text:
        return ""
    text = _CITATION.sub("", text)
    text = _MD_LINK.sub(r"\1", text)
    text = _HTML.sub(" ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _norm_ws(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _truncate(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    end = max(cut.rfind(". "), cut.rfind(".\n"))
    if end > limit * 0.5:
        return cut[: end + 1]
    cut = cut.rsplit(" ", 1)[0]
    if cut.count("(") > cut.count(")"):          # do not leave an unclosed bracket
        cut = cut[: cut.rfind("(")].rstrip(" ,;:")
    return cut + "…"


_FIELDS = [
    "chunk_id", "incident_id", "knowledge_source", "knowledge_set", "section", "replaced_by",
    "attack_type", "incident_description", "target_system", "outcome", "attack_severity",
    "source_type", "source_reference", "source_title", "data_origin",
    "mapping_method", "mapping_confidence",
    "mitre_tactic", "mitre_technique_id", "mitre_technique_name", "mitre_description",
    "mitre_mitigations", "mitre_detection",
    "nist_function", "nist_category", "nist_subcategory", "nist_description",
    "detection_indicators", "investigation_steps", "containment_steps",
    "eradication_steps", "recovery_steps", "recommended_response",
    "chunk_text", "combined_knowledge_text", "search_text",
]


def _new_record(**values) -> Dict:
    rec = {k: "" for k in _FIELDS}
    rec.update(values)
    rec["knowledge_set"] = rec["knowledge_set"] or rec["knowledge_source"]
    rec["search_text"] = rec["search_text"] or rec["chunk_text"]
    rec["combined_knowledge_text"] = rec["combined_knowledge_text"] or rec["chunk_text"][:1000]
    rec["chunk_index"] = 0
    rec["total_chunks"] = 1
    return rec


def _number_chunks(records: List[Dict]) -> None:
    for i, rec in enumerate(records):
        rec["chunk_index"] = i
        rec["total_chunks"] = len(records)


# --------------------------------------------------------------------------- MITRE
def load_mitre(path: Path, only_techniques: Optional[set] = None) -> List[Dict]:
    """One technique -> up to three chunks: description, detection, mitigations."""
    with open(path, "r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if "id" in o}

    def active(o: Dict) -> bool:
        return not o.get("revoked") and not o.get("x_mitre_deprecated")

    for o in objects:
        if o.get("type") == "x-mitre-collection":
            logger.info("MITRE collection: %s version %s", o.get("name"), o.get("x_mitre_version"))
            break

    # technique id -> [(mitigation name, how it applies)]
    mitigations: Dict[str, List[Tuple[str, str]]] = {}
    for o in objects:
        if o.get("type") != "relationship" or o.get("relationship_type") != "mitigates":
            continue
        if not active(o):
            continue
        src = by_id.get(o.get("source_ref", ""))
        if not src or src.get("type") != "course-of-action" or not active(src):
            continue
        how = clean_text(o.get("description") or src.get("description", ""))
        mitigations.setdefault(o["target_ref"], []).append((src.get("name", ""), how))

    # Detection guidance. ATT&CK v18+ stores it as detection strategies -> analytics (older files used
    # x_mitre_detection on the technique itself, which is handled below as a fallback).
    strategies = {o["id"]: o for o in objects if o.get("type") == "x-mitre-detection-strategy" and active(o)}
    analytics = {o["id"]: o for o in objects if o.get("type") == "x-mitre-analytic" and active(o)}
    detections: Dict[str, List[Tuple[str, str]]] = {}   # technique id -> [(platforms, analytic text)]
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "detects" and active(o):
            strat = strategies.get(o.get("source_ref", ""))
            if not strat:
                continue
            for aref in strat.get("x_mitre_analytic_refs", []):
                a = analytics.get(aref)
                text = clean_text((a or {}).get("description", ""))
                if text:
                    detections.setdefault(o["target_ref"], []).append((", ".join(a.get("x_mitre_platforms", [])), text))

    def ext_id(o: Dict) -> Tuple[str, str]:
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"], ref.get("url", "")
        return "", ""

    # Revoked techniques that point to a replacement. Wazuh rules often still emit the old ID
    # (for example T1562.001, now T1685), so SERC keeps a small "renamed" record for each.
    revoked_by: Dict[str, Dict] = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            old, new = by_id.get(o.get("source_ref", "")), by_id.get(o.get("target_ref", ""))
            if old and new and old.get("type") == "attack-pattern" and new.get("type") == "attack-pattern" and active(new):
                revoked_by[old["id"]] = new
    wanted = set(only_techniques) if only_techniques else None
    if wanted:
        for oid, new in revoked_by.items():
            old_tid, new_tid = ext_id(by_id[oid])[0], ext_id(new)[0]
            if old_tid and new_tid and old_tid.split(".")[0] in only_techniques:
                wanted.add(new_tid.split(".")[0])

    records: List[Dict] = []
    for oid, new in revoked_by.items():
        old = by_id[oid]
        old_tid, _ = ext_id(old)
        new_tid, new_url = ext_id(new)
        if not old_tid or not new_tid or (only_techniques and old_tid.split(".")[0] not in only_techniques):
            continue
        records.append(_new_record(
            knowledge_source=SRC_MITRE, section="renamed", replaced_by=new_tid,
            chunk_id=f"MITRE-{old_tid}#renamed", incident_id=f"MITRE-{old_tid}",
            attack_type=old.get("name", ""), source_type="official_framework",
            source_title="MITRE ATT&CK Enterprise", data_origin="official",
            mapping_method="official_source", mapping_confidence="Official",
            mitre_technique_id=old_tid, mitre_technique_name=old.get("name", ""),
            source_reference=f"MITRE ATT&CK {old_tid} (revoked; replaced by {new_tid})",
            chunk_text=(f"MITRE ATT&CK {old_tid} {old.get('name', '')} was revoked in the current ATT&CK release. "
                        f"It is now {new_tid} {new.get('name', '')}."),
        ))

    for o in objects:
        if o.get("type") != "attack-pattern" or not active(o):
            continue
        tid, url = ext_id(o)
        if not tid:
            continue
        if wanted is not None and tid.split(".")[0] not in wanted:
            continue

        name = o.get("name", "")
        tactics = [
            p["phase_name"].replace("-", " ").title()
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        tactic_txt = ", ".join(tactics)
        description = clean_text(o.get("description", ""))
        detection = clean_text(o.get("x_mitre_detection", ""))
        dets = detections.get(o["id"], [])
        if dets:  # newer ATT&CK: use up to three analytics, skipping near-duplicates
            seen_d, parts = set(), []
            for plats, text in dets:
                key = text[:80].lower()
                if key in seen_d:
                    continue
                seen_d.add(key)
                parts.append(f"- {_truncate(text, 480)}" + (f" (Platforms: {plats})" if plats else ""))
                if len(parts) == 3:
                    break
            detection = "\n".join(parts)
        mits = mitigations.get(o["id"], [])

        common = dict(
            knowledge_source=SRC_MITRE,
            incident_id=f"MITRE-{tid}",
            attack_type=name,
            source_type="official_framework",
            source_title="MITRE ATT&CK Enterprise",
            data_origin="official",
            mapping_method="official_source",
            mapping_confidence="Official",
            mitre_tactic=tactic_txt,
            mitre_technique_id=tid,
            mitre_technique_name=name,
            mitre_description=_truncate(description, 800),
            mitre_mitigations="; ".join(n for n, _ in mits),
            mitre_detection=_truncate(detection, 600),
        )

        chunks: List[Dict] = []
        head = f"MITRE ATT&CK {tid} {name}. Tactic: {tactic_txt}."
        chunks.append(_new_record(
            **common, section="description",
            chunk_id=f"MITRE-{tid}#description",
            incident_description=_truncate(description, 220),
            source_reference=f"MITRE ATT&CK {tid} ({url})" if url else f"MITRE ATT&CK {tid}",
            chunk_text=f"{head}\n{_truncate(description, 1500)}",
        ))
        if detection:
            text = f"Detection guidance for MITRE ATT&CK {tid} {name}:\n{_truncate(detection, 1500)}"
            chunks.append(_new_record(
                **common, section="detection",
                chunk_id=f"MITRE-{tid}#detection",
                incident_description=_truncate(description, 220),
                source_reference=f"MITRE ATT&CK {tid} detection ({url})" if url else f"MITRE ATT&CK {tid} detection",
                investigation_steps=text, detection_indicators=text, chunk_text=text,
            ))
        if mits:
            lines = [f"- {n}: {_truncate(h, 220)}" if h else f"- {n}" for n, h in mits]
            text = f"Mitigations for MITRE ATT&CK {tid} {name}:\n" + "\n".join(lines)
            text = _truncate(text, 1800)
            chunks.append(_new_record(
                **common, section="mitigations",
                chunk_id=f"MITRE-{tid}#mitigations",
                incident_description=_truncate(description, 220),
                source_reference=f"MITRE ATT&CK {tid} mitigations ({url})" if url else f"MITRE ATT&CK {tid} mitigations",
                recommended_response=text, chunk_text=text,
            ))
        _number_chunks(chunks)
        records.extend(chunks)
    return records


# --------------------------------------------------------------------------- NIST CSF 2.0
_FUN = re.compile(r"^([A-Za-z ]+?)\s*\(([A-Z]{2})\):\s*(.+)$", re.S)
_CAT = re.compile(r"^(.*?)\s*\(([A-Z]{2}\.[A-Z]{2})\):\s*(.+)$", re.S)
_SUB = re.compile(r"^([A-Z]{2}\.[A-Z]{2}-\d{2}):\s*(.+)$", re.S)


def _cell(row, i: int) -> str:
    if row is None or i >= len(row) or row[i] is None:
        return ""
    return str(row[i]).strip()


def load_nist_csf(path: Path) -> List[Dict]:
    """Functions, categories and subcategories (with implementation examples).
    Informative references are skipped on purpose: they are long lists of IDs that add noise."""
    from openpyxl import load_workbook

    wb = load_workbook(path, read_only=True, data_only=True)
    ws = wb["CSF 2.0"] if "CSF 2.0" in wb.sheetnames else wb[wb.sheetnames[-1]]
    rows = list(ws.iter_rows(values_only=True))
    start = next((i + 1 for i, r in enumerate(rows) if _cell(r, 0) == "Function"), 2)

    records: List[Dict] = []
    fn_name = fn_code = cat_name = cat_code = ""
    skip_cat = False
    title = "NIST Cybersecurity Framework 2.0"

    for row in rows[start:]:
        fcell, ccell, scell, ecell = (_cell(row, i) for i in range(4))

        if fcell:
            m = _FUN.match(fcell)
            if not m or "[Withdrawn" in fcell:
                continue
            fn_name, fn_code = m.group(1).strip().title(), m.group(2)
            desc = clean_text(m.group(3))
            text = f"NIST CSF 2.0 Function {fn_name} ({fn_code}): {desc}"
            records.append(_new_record(
                knowledge_source=SRC_NIST, section="function",
                chunk_id=f"NIST-{fn_code}#function", incident_id=f"NIST-{fn_code}",
                attack_type=f"{fn_name} function", incident_description=desc,
                source_type="official_framework", source_title=title, data_origin="official",
                source_reference=f"NIST CSF 2.0, Function {fn_code}",
                mapping_method="official_source", mapping_confidence="Official",
                nist_function=fn_name, nist_description=desc,
                chunk_text=text,
            ))
            continue

        if ccell:
            if "[Withdrawn" in ccell:
                skip_cat = True
                continue
            m = _CAT.match(ccell)
            if not m:
                continue
            skip_cat = False
            cat_name, cat_code = m.group(1).strip(), m.group(2)
            desc = clean_text(m.group(3))
            text = f"NIST CSF 2.0 Category {cat_name} ({cat_code}) under {fn_name}: {desc}"
            records.append(_new_record(
                knowledge_source=SRC_NIST, section="category",
                chunk_id=f"NIST-{cat_code}#category", incident_id=f"NIST-{cat_code}",
                attack_type=cat_name, incident_description=desc,
                source_type="official_framework", source_title=title, data_origin="official",
                source_reference=f"NIST CSF 2.0, Category {cat_code}",
                mapping_method="official_source", mapping_confidence="Official",
                nist_function=fn_name, nist_category=f"{cat_code} {cat_name}", nist_description=desc,
                chunk_text=text,
            ))
            continue

        if scell:
            if skip_cat or "[Withdrawn" in scell:
                continue
            m = _SUB.match(scell)
            if not m:
                continue
            code, outcome = m.group(1), clean_text(m.group(2))
            examples = "\n".join(l.strip() for l in ecell.splitlines() if l.strip())
            text = (
                f"NIST CSF 2.0 {code}: {outcome}\n"
                f"Function: {fn_name}. Category: {cat_name} ({cat_code})."
            )
            if examples:
                text += "\nImplementation examples:\n" + _truncate(examples, 1300)
            records.append(_new_record(
                knowledge_source=SRC_NIST, section="subcategory",
                chunk_id=f"NIST-{code}", incident_id=f"NIST-{code}",
                attack_type=cat_name, incident_description=outcome,
                source_type="official_framework", source_title=title, data_origin="official",
                source_reference=f"NIST CSF 2.0, {code}",
                mapping_method="official_source", mapping_confidence="Official",
                nist_function=fn_name, nist_category=f"{cat_code} {cat_name}",
                nist_subcategory=f"{code}: {outcome}", nist_description=outcome,
                recommended_response=_truncate(examples, 1300),
                chunk_text=text,
            ))
    return records


# --------------------------------------------------------------------------- Incident response PDFs
_STEP_RE = re.compile(
    r"^\s*(?:\d+\s*[.)\-:]?\s*)?(Preparation|Identification|Containment|Remediation|Recovery|Aftermath)\b",
    re.I,
)
_IRM_HEADER = re.compile(r"^IRM\s*#\d+", re.I)                      # running page header of IRM playbooks
_PAGE_NO = re.compile(r"^(page\s*)?\d+(\s*(/|of)\s*\d+)?$", re.I)  # "7", "Page 7", "7 of 9"
_STEP_FIELD = {
    "Identification": "investigation_steps",
    "Containment": "containment_steps",
    "Remediation": "eradication_steps",
    "Recovery": "recovery_steps",
}


def read_pdf_pages(path: Path) -> List[str]:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    pages = []
    for page in reader.pages:
        try:
            pages.append(page.extract_text() or "")
        except Exception:  # a single bad page should not stop the run
            pages.append("")
    return pages


def _skip_page(page: str) -> bool:
    return len(page.strip()) < 150 or page.count("....") > 5  # blank pages, tables of contents


def chunk_pages(
    pages: List[str],
    detect_sections: bool = False,
    max_chars: int = 1100,
    overlap: int = 150,
) -> List[Tuple[str, int, str]]:
    """Split page text into (section, page, text) chunks.
    With detect_sections=True, IRM step headings (Preparation ... Aftermath) start a new chunk."""
    out: List[Tuple[str, int, str]] = []
    section: Optional[str] = "Overview" if detect_sections else None
    buf, buf_page = "", 1

    # Running headers/footers: short lines that repeat on several pages, plus known patterns
    usable = [p for p in pages if not _skip_page(p)]
    counts: Counter = Counter()
    for page in usable:
        for line in {l.strip() for l in page.splitlines() if l.strip() and len(l.strip()) < 80}:
            counts[line] += 1
    min_pages = max(3, int(len(usable) * 0.4))
    repeated = {line for line, c in counts.items() if c >= min_pages}

    def is_noise(line: str) -> bool:
        return (
            line in repeated
            or "TLP:" in line
            or bool(_IRM_HEADER.match(line))
            or bool(_PAGE_NO.match(line))
        )

    def emit(text: str, sec: Optional[str], page: int) -> str:
        text = _norm_ws(text)
        if len(text) >= 80:
            out.append((sec if sec else f"Page {page}", page, text))
        return text

    for pageno, page in enumerate(pages, start=1):
        if _skip_page(page):
            continue
        for raw in page.splitlines():
            line = raw.strip()
            if not line or is_noise(line):
                continue
            if detect_sections:
                m = _STEP_RE.match(line)
                if m and len(line) < 60:
                    emit(buf, section, buf_page)
                    buf, buf_page = "", pageno
                    section = m.group(1).title()
            if not buf:
                buf, buf_page = line, pageno
            else:
                buf += ("\n" if _BULLET.match(line) else " ") + line
            if len(buf) >= max_chars:
                text = emit(buf, section, buf_page)
                tail = text[-overlap:] if overlap else ""
                if " " in tail:
                    tail = tail.split(" ", 1)[1]
                buf, buf_page = tail, pageno
    emit(buf, section, buf_page)
    return out


def _irm_title(stem: str) -> Tuple[str, str]:
    m = re.match(r"IRM-(\d+)-(.*)", stem)
    if not m:
        return stem, stem
    num, rest = m.group(1), m.group(2).replace("_", " ").replace("-", " ")
    rest = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", rest)  # WormInfection -> Worm Infection
    return f"IRM-{num}", f"IRM-{num} {rest}".strip()


_NIST_TITLES = {
    "r3": ("NIST SP 800-61 Rev. 3", "Incident Response Recommendations and Considerations for Cybersecurity Risk Management"),
    "r2": ("NIST SP 800-61 Rev. 2", "Computer Security Incident Handling Guide"),
}


def _pdf_records(path: Path, doc_id: str, label: str, title: str, source_title: str,
                 detect_sections: bool) -> List[Dict]:
    pages = read_pdf_pages(path)
    chunks = chunk_pages(pages, detect_sections=detect_sections)
    if not chunks:
        logger.warning("No extractable text in %s (scanned PDF?). Skipped.", path.name)
        return []
    records: List[Dict] = []
    for n, (section, page, text) in enumerate(chunks):
        fields = dict(
            knowledge_source=SRC_IR, section=section,
            chunk_id=f"{doc_id}#{n:03d}", incident_id=doc_id,
            attack_type=title, incident_description=_truncate(text, 200),
            source_type="official_guide", source_title=source_title, data_origin="official",
            source_reference=f"{label}, p.{page}, {section}" if detect_sections else f"{label}, p.{page}",
            recommended_response=text, chunk_text=f"{title} ({section}):\n{text}",
        )
        step_field = _STEP_FIELD.get(section)
        if step_field:
            fields[step_field] = text
        records.append(_new_record(**fields))
    _number_chunks(records)
    return records


def load_incident_response(data_dir: Path, include_rev2: bool = False) -> List[Dict]:
    records: List[Dict] = []

    irm_dirs = [p for p in data_dir.iterdir() if p.is_dir() and p.name.lower().startswith("irm")]
    for irm_dir in irm_dirs:
        for pdf in sorted(irm_dir.rglob("*.pdf")):
            doc_id, title = _irm_title(pdf.stem)
            try:
                records.extend(_pdf_records(
                    pdf, doc_id, label=title, title=title,
                    source_title="CERT Societe Generale IRM", detect_sections=True))
            except Exception as exc:
                logger.warning("Could not read %s: %s", pdf.name, exc)

    wanted = ["r3"] + (["r2"] if include_rev2 else [])
    for pdf in sorted(data_dir.glob("*.pdf")):
        low = pdf.name.lower()
        for rev in wanted:
            if f"800-61{rev}" in low:
                label, title = _NIST_TITLES[rev]
                try:
                    records.extend(_pdf_records(
                        pdf, f"NIST-SP-800-61{rev}", label=label, title=f"{label}: {title}",
                        source_title=label, detect_sections=False))
                except Exception as exc:
                    logger.warning("Could not read %s: %s", pdf.name, exc)
    return records


# --------------------------------------------------------------------------- top level
def dedupe(records: List[Dict]) -> List[Dict]:
    """Drop chunks whose text is (almost) identical to one already kept."""
    seen, kept = set(), []
    for rec in records:
        norm = re.sub(r"\s+", " ", rec["chunk_text"].lower()).strip()[:300]
        key = hashlib.sha1(norm.encode("utf-8")).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        kept.append(rec)
    return kept


def load_all(data_dir: Path, quick: bool = False, include_rev2: bool = False) -> Dict[str, List[Dict]]:
    data_dir = Path(data_dir)
    out: Dict[str, List[Dict]] = {s: [] for s in ALL_SOURCES}

    mitre_path = data_dir / "enterprise-attack.json"
    if mitre_path.exists():
        out[SRC_MITRE] = load_mitre(mitre_path, QUICK_TECHNIQUES if quick else None)
    else:
        logger.warning("Missing %s", mitre_path)

    csf_candidates = list(data_dir.glob("csf2*.xlsx")) + list(data_dir.glob("*csf*.xlsx"))
    if csf_candidates:
        out[SRC_NIST] = load_nist_csf(csf_candidates[0])
    else:
        logger.warning("Missing NIST CSF 2.0 workbook (csf2.xlsx) in %s", data_dir)

    out[SRC_IR] = load_incident_response(data_dir, include_rev2=include_rev2)
    if not out[SRC_IR]:
        logger.warning("No incident-response PDFs found (IRM folder / NIST SP 800-61).")

    for src in out:
        out[src] = dedupe(out[src])
    return out
