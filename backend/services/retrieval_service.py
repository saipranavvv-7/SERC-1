"""
Retrieval service using Qdrant vector database.
Supports local persistent storage and remote Qdrant instances.
Preserves source IDs, provenance, and MITRE/NIST cybersecurity metadata.
"""
import re
import uuid
import hashlib
import logging
from typing import List, Dict, Any, Optional
from qdrant_client import QdrantClient
from qdrant_client.models import (
    VectorParams,
    Distance,
    PointStruct,
    Filter,
    FieldCondition,
    MatchValue,
)
from backend.config import settings
from backend.services.embedding_service import embedding_service
from backend.services.knowledge_sources import ALL_SOURCES

logger = logging.getLogger("serc.retrieval_service")

# Deterministic namespace for converting incident_id (INC-000001) to a valid Qdrant UUID
UUID_NAMESPACE = uuid.UUID("3c4d5e6f-7a8b-9c0d-1e2f-3a4b5c6d7e8f")


class RetrievalService:
    def __init__(self):
        self.collection_name = settings.qdrant_collection
        self._client: Optional[QdrantClient] = None

    @property
    def client(self) -> QdrantClient:
        if self._client is None:
            self._client = self._init_client()
        return self._client

    def close(self):
        """Closes the client connection and releases any local storage locks."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def _init_client(self) -> QdrantClient:
        """Initializes embedded disk Qdrant or remote client based on configuration."""
        if settings.qdrant_url:
            logger.info(f"Connecting to remote Qdrant instance at {settings.qdrant_url}")
            return QdrantClient(
                url=settings.qdrant_url,
                api_key=settings.qdrant_api_key or None,
            )
        else:
            storage_path = settings.qdrant_storage_dir
            if storage_path:
                storage_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Initializing embedded persistent Qdrant at {storage_path}")
                return QdrantClient(path=str(storage_path))
            else:
                logger.info("Initializing in-memory Qdrant instance")
                return QdrantClient(":memory:")

    def ensure_collection(self, recreate: bool = False):
        """Ensures the collection exists with cosine distance and correct vector size."""
        cl = self.client
        exists = cl.collection_exists(self.collection_name)
        if exists and recreate:
            logger.warning(f"Recreating existing collection: {self.collection_name}")
            cl.delete_collection(self.collection_name)
            exists = False

        if not exists:
            dim = embedding_service.dimension
            logger.info(f"Creating Qdrant collection '{self.collection_name}' (vector size: {dim})")
            cl.create_collection(
                collection_name=self.collection_name,
                vectors_config=VectorParams(size=dim, distance=Distance.COSINE),
            )

    def upsert_batch(self, records: List[Dict[str, Any]], embeddings: List[List[float]]):
        """Upserts a batch of chunked records with deterministic UUIDs."""
        self.ensure_collection(recreate=False)
        points = []

        for record, vec in zip(records, embeddings):
            # Prefer chunk_id if available, fallback to incident_id
            chunk_id = str(record.get("chunk_id", "")).strip()
            inc_id = str(record.get("incident_id", "")).strip()
            unique_key = chunk_id if chunk_id else inc_id

            # Generate deterministic UUID so repeated ingestion won't create duplicates
            point_id = str(uuid.uuid5(UUID_NAMESPACE, unique_key)) if unique_key else str(uuid.uuid4())

            chunk_text = record.get("chunk_text") or record.get("combined_knowledge_text") or record.get("incident_description", "")
            knowledge_src = record.get("knowledge_source") or record.get("knowledge_set", "")

            payload = {
                "chunk_id": chunk_id or f"{inc_id}#chunk-0",
                "chunk_index": record.get("chunk_index", 0),
                "total_chunks": record.get("total_chunks", 1),
                "incident_id": inc_id,
                "knowledge_source": knowledge_src,
                "section": record.get("section", "general"),
                "replaced_by": record.get("replaced_by", ""),
                "attack_type": record.get("attack_type", ""),
                "incident_description": record.get("incident_description", ""),
                "target_system": record.get("target_system", ""),
                "outcome": record.get("outcome", ""),
                "attack_severity": record.get("attack_severity", ""),
                "knowledge_set": record.get("knowledge_set", knowledge_src),
                "source_type": record.get("source_type", ""),
                "source_reference": record.get("source_reference", ""),
                "source_title": record.get("source_title", ""),
                "data_origin": record.get("data_origin", ""),
                "mapping_method": record.get("mapping_method", ""),
                "mapping_confidence": record.get("mapping_confidence", ""),
                "mitre_tactic": record.get("mitre_tactic", ""),
                "mitre_technique_id": record.get("mitre_technique_id", ""),
                "mitre_technique_name": record.get("mitre_technique_name", ""),
                "mitre_description": record.get("mitre_description", ""),
                "mitre_mitigations": record.get("mitre_mitigations", ""),
                "mitre_detection": record.get("mitre_detection", ""),
                "nist_function": record.get("nist_function", ""),
                "nist_category": record.get("nist_category", ""),
                "nist_subcategory": record.get("nist_subcategory", ""),
                "nist_description": record.get("nist_description", ""),
                "detection_indicators": record.get("detection_indicators", ""),
                "investigation_steps": record.get("investigation_steps", ""),
                "containment_steps": record.get("containment_steps", ""),
                "eradication_steps": record.get("eradication_steps", ""),
                "recovery_steps": record.get("recovery_steps", ""),
                "recommended_response": record.get("recommended_response", ""),
                "chunk_text": chunk_text[:2000],
                "combined_knowledge_text": record.get("combined_knowledge_text", "")[:1000],
            }

            points.append(PointStruct(id=point_id, vector=vec, payload=payload))

        self.client.upsert(collection_name=self.collection_name, points=points)

    # ------------------------------------------------------------------ search
    LOW_CONFIDENCE_THRESHOLD = 0.50   # flag weak matches in the UI; tune after checking real scores
    MAX_CHUNKS_PER_DOCUMENT = 2       # stop one technique / playbook from filling every slot

    def _has_points(self) -> bool:
        if not self.client.collection_exists(self.collection_name):
            logger.info("Qdrant collection does not exist yet; returning empty evidence.")
            return False
        if self.client.count(collection_name=self.collection_name).count == 0:
            logger.info("Qdrant collection has 0 points; returning empty evidence.")
            return False
        return True

    def _search_raw(self, query_vec: List[float], limit: int, knowledge_set: Optional[str] = None) -> List[Dict[str, Any]]:
        """One vector search (optionally limited to one knowledge source)."""
        query_filter = None
        if knowledge_set:
            query_filter = Filter(
                must=[FieldCondition(key="knowledge_source", match=MatchValue(value=knowledge_set))]
            )
        search_result = self.client.query_points(
            collection_name=self.collection_name,
            query=query_vec,
            query_filter=query_filter,
            limit=limit,
            with_payload=True,
        )

        return [
            self._payload_to_hit(hit.payload or {}, round(float(hit.score), 4) if hit.score is not None else 0.0)
            for hit in search_result.points
        ]

    def _payload_to_hit(self, payload: Dict[str, Any], score: float) -> Dict[str, Any]:
        chunk_txt = payload.get("chunk_text") or ""
        text_snippet = (
            chunk_txt
            or payload.get("incident_description")
            or payload.get("combined_knowledge_text")
            or f"Incident {payload.get('incident_id')} - {payload.get('attack_type')}"
        )
        return {
            "incident_id": payload.get("incident_id", ""),
            "chunk_id": payload.get("chunk_id", ""),
            "knowledge_source": payload.get("knowledge_source") or payload.get("knowledge_set", ""),
            "section": payload.get("section", ""),
            "replaced_by": payload.get("replaced_by", ""),
            "similarity_score": score,
            "low_confidence": score < self.LOW_CONFIDENCE_THRESHOLD,
            "attack_type": payload.get("attack_type", ""),
            "incident_description": payload.get("incident_description", ""),
            "mitre_tactic": payload.get("mitre_tactic", ""),
            "mitre_technique_id": payload.get("mitre_technique_id", ""),
            "mitre_technique_name": payload.get("mitre_technique_name", ""),
            "mitre_description": payload.get("mitre_description", ""),
            "mitre_mitigations": payload.get("mitre_mitigations", ""),
            "nist_function": payload.get("nist_function", ""),
            "nist_category": payload.get("nist_category", ""),
            "nist_subcategory": payload.get("nist_subcategory", ""),
            "knowledge_set": payload.get("knowledge_set", ""),
            "source_type": payload.get("source_type", ""),
            "source_title": payload.get("source_title", ""),
            "data_origin": payload.get("data_origin", ""),
            "source_reference": payload.get("source_reference", ""),
            "mapping_confidence": payload.get("mapping_confidence", ""),
            "detection_indicators": payload.get("detection_indicators", ""),
            "investigation_steps": payload.get("investigation_steps", ""),
            "recommended_response": payload.get("recommended_response", ""),
            "chunk_text": chunk_txt,
            "snippet": text_snippet[:350],
        }

    def lookup_technique(self, technique_id: str, limit: int = 6) -> List[Dict[str, Any]]:
        """Exact lookup of every stored chunk for one MITRE technique ID (the paper's direct MITRE lookup)."""
        if not technique_id or not self._has_points():
            return []
        flt = Filter(must=[FieldCondition(key="mitre_technique_id", match=MatchValue(value=technique_id))])
        points, _ = self.client.scroll(
            collection_name=self.collection_name,
            scroll_filter=flt, limit=limit, with_payload=True, with_vectors=False,
        )
        hits = [self._payload_to_hit(p.payload or {}, 1.0) for p in points]
        order = {"description": 0, "mitigations": 1, "detection": 2}
        return sorted(hits, key=lambda h: order.get(h["section"], 9))

    def existing_chunk_ids(self, chunk_ids: List[str]) -> set:
        """Which of these chunk IDs are already stored (lets re-ingestion skip finished work)."""
        if not chunk_ids or not self.client.collection_exists(self.collection_name):
            return set()
        pid = {c: str(uuid.uuid5(UUID_NAMESPACE, c)) for c in chunk_ids}
        found = self.client.retrieve(
            collection_name=self.collection_name, ids=list(pid.values()),
            with_payload=False, with_vectors=False,
        )
        stored = {str(r.id) for r in found}
        return {c for c, p in pid.items() if p in stored}

    @staticmethod
    def _text_key(hit: Dict[str, Any]) -> str:
        text = hit.get("chunk_text") or hit.get("snippet") or ""
        norm = re.sub(r"\s+", " ", text.lower()).strip()[:300]
        return hashlib.sha1(norm.encode("utf-8")).hexdigest()

    @classmethod
    def balance_hits(cls, per_source: Dict[str, List[Dict[str, Any]]], top_k: int) -> List[Dict[str, Any]]:
        """
        1. drop chunks whose text is (almost) identical to one already kept,
        2. allow at most MAX_CHUNKS_PER_DOCUMENT chunks from one document,
        3. take results round-robin across knowledge sources (MITRE, NIST, incident response),
        4. return them sorted by similarity score.
        """
        seen_text = set()
        lists: List[List[Dict[str, Any]]] = []
        for hits in per_source.values():
            kept, per_doc = [], {}
            for h in sorted(hits, key=lambda x: -x["similarity_score"]):
                key = cls._text_key(h)
                doc = h.get("incident_id", "")
                if key in seen_text or per_doc.get(doc, 0) >= cls.MAX_CHUNKS_PER_DOCUMENT:
                    continue
                seen_text.add(key)
                per_doc[doc] = per_doc.get(doc, 0) + 1
                kept.append(h)
            if kept:
                lists.append(kept)

        chosen: List[Dict[str, Any]] = []
        rank = 0
        while len(chosen) < top_k and any(rank < len(l) for l in lists):
            for l in lists:
                if rank < len(l) and len(chosen) < top_k:
                    chosen.append(l[rank])
            rank += 1
        return sorted(chosen, key=lambda x: -x["similarity_score"])

    def search_evidence(
        self,
        query: str,
        top_k: int = 5,
        knowledge_set: Optional[str] = None,
        fetch_k: int = 12,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve diverse evidence. Without knowledge_set, each knowledge source is searched
        separately (as in the paper's three collections) and the results are de-duplicated
        and balanced. Existing callers get this automatically.
        """
        if not self._has_points():
            return []
        query_vec = embedding_service.embed_query(query)
        sources = [knowledge_set] if knowledge_set else list(ALL_SOURCES)
        per_source = {s: self._search_raw(query_vec, fetch_k, s) for s in sources}
        return self.balance_hits(per_source, top_k)

    def get_stats(self) -> Dict[str, Any]:
        """Returns collection stats for the UI and health checks."""
        try:
            if not self.client.collection_exists(self.collection_name):
                return {"exists": False, "total_vectors": 0, "collection_name": self.collection_name}
            count_res = self.client.count(collection_name=self.collection_name)
            return {
                "exists": True,
                "total_vectors": count_res.count,
                "collection_name": self.collection_name
            }
        except Exception as e:
            return {"exists": False, "error": str(e), "total_vectors": 0}


retrieval_service = RetrievalService()
