"""REST API for SERC. Thin layer: the logic lives in backend/services/."""
from __future__ import annotations

import json
import logging
import threading
from functools import lru_cache
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from backend.config import settings
from backend.services import alert_parser as ap
from backend.services import analysis_service as an
from backend.services.feedback_service import FeedbackService
from backend.services.llm_client import LLMClient
from backend.services.retrieval_service import retrieval_service

logger = logging.getLogger("serc.routes")
router = APIRouter(prefix="/api")

llm = LLMClient(settings)
feedback = FeedbackService(settings.feedback_db_file)

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_IMAGE_BYTES = 5 * 1024 * 1024
TEXT_EXT = {".json", ".log", ".txt", ".csv", ".ndjson", ".jsonl", ""}
IMAGE_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}


_kb_lock = threading.Lock()  # embedded Qdrant and the embedding model are not built for parallel requests


class RetrieverAdapter:
    def search(self, query: str, top_k: int = 5):
        with _kb_lock:
            return retrieval_service.search_evidence(query, top_k=top_k)

    def lookup_technique(self, tid: str):
        with _kb_lock:
            return retrieval_service.lookup_technique(tid)


retriever = RetrieverAdapter()


@lru_cache(maxsize=1)
def _samples() -> List[Dict[str, Any]]:
    path = settings.sample_alerts_file
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ status
@router.get("/health")
def health():
    with _kb_lock:
        stats = retrieval_service.get_stats()
    return {
        "status": "ok",
        "vectors": stats.get("total_vectors", 0),
        "collection_error": stats.get("error"),
        "mode": "live" if llm.text_live else "offline",
        "vision_available": llm.vision_live,
        "embedding_model": settings.embedding_model_name,
        "llm_model": settings.openai_model if llm.text_live else "",
    }


# ------------------------------------------------------------------ samples
@router.get("/alerts/samples")
def list_samples():
    rows = []
    for a in _samples():
        v = ap.view_of(a)
        rows.append({"id": v["alert_id"], "rule_id": v["rule_id"], "level": v["level"], "severity": v["severity"],
                     "agent": v["agent_name"], "description": v["description"],
                     "label": f"[{v['severity']}] {v['description']} ({v['agent_name']})"})
    return rows


@router.get("/alerts/samples/{alert_id}")
def get_sample(alert_id: str):
    for a in _samples():
        if ap.view_of(a)["alert_id"] == alert_id:
            return a
    raise HTTPException(404, "Sample alert not found")


# ------------------------------------------------------------------ input handling
@router.post("/alerts/ingest")
def ingest(text: Optional[str] = Form(None), file: Optional[UploadFile] = File(None)):
    """Accepts pasted text or an uploaded file (json, log, txt, csv, png, jpg) and returns a normalised alert."""
    if file is not None and file.filename:
        name = file.filename.lower()
        ext = name[name.rfind("."):] if "." in name else ""
        if ext in IMAGE_MIME:
            data = file.file.read(MAX_IMAGE_BYTES + 1)
            if len(data) > MAX_IMAGE_BYTES:
                return {"ok": False, "message": "The image is larger than 5 MB. Please use a smaller screenshot."}
            if not llm.vision_live:
                return {"ok": False, "code": "vision_unavailable",
                        "message": "Reading images needs live mode (an OpenAI key in backend/.env), which is not set up here. "
                                   "Please paste the alert text or upload the JSON or log file instead."}
            try:
                alert = llm.read_alert_image(data, IMAGE_MIME[ext])
            except Exception as exc:
                logger.warning("Image reading failed: %s", exc)
                return {"ok": False, "message": "The image could not be read. Try a clearer screenshot, or paste the text instead."}
            return {"ok": True, "source_type": "image", "alert": alert, "extracted": ap._extracted_fields(alert),
                    "warnings": ["Details were read from an image and can contain mistakes. Please check them before analysing."],
                    "needs_confirmation": True}
        if ext not in TEXT_EXT:
            return {"ok": False, "message": f"'{ext}' files are not supported. Use .json, .log, .txt, .csv, .png or .jpg."}
        raw = file.file.read(MAX_TEXT_BYTES + 1)
        if len(raw) > MAX_TEXT_BYTES:
            return {"ok": False, "message": "The file is larger than 2 MB. Please upload a smaller file."}
        return ap.parse_input(raw.decode("utf-8", errors="replace"), filename=file.filename)
    return ap.parse_input(text or "")


# ------------------------------------------------------------------ analysis
class AnalyzeRequest(BaseModel):
    alert: Dict[str, Any]


@router.post("/alerts/analyze")
def analyze(req: AnalyzeRequest):
    result = an.analyze_alert(req.alert, retriever, llm=llm, top_k=settings.top_k_retrieval)
    if not result.get("ok"):
        raise HTTPException(422, "; ".join(result.get("errors", ["Invalid alert"])))
    return result


@router.post("/alerts/compare")
def compare(req: AnalyzeRequest):
    """Live mode only: the same alert answered with retrieved evidence and without it (the paper's missing baseline)."""
    return an.compare_rag(req.alert, retriever, llm, top_k=settings.top_k_retrieval)


class ChatRequest(BaseModel):
    alert: Optional[Dict[str, Any]] = None
    question: str


@router.post("/alerts/chat")
def chat(req: ChatRequest):
    return an.answer_question(req.alert or {}, req.question, retriever, llm=llm)


# ------------------------------------------------------------------ feedback
class FeedbackRequest(BaseModel):
    alert_id: str
    claim_id: str
    decision: str
    claim_text: str = ""
    note: str = ""


@router.post("/feedback")
def save_feedback(req: FeedbackRequest):
    try:
        return feedback.save(req.alert_id, req.claim_id, req.decision, req.claim_text, req.note)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/feedback/{alert_id}")
def get_feedback(alert_id: str):
    return feedback.list_for_alert(alert_id)
