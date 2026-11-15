"""
Ingest SERC's official knowledge sources into Qdrant.

    MITRE ATT&CK (enterprise-attack.json)  ->  knowledge_source = "mitre"
    NIST CSF 2.0 (csf2.xlsx)                ->  knowledge_source = "nist"
    CERT-SG IRM PDFs + NIST SP 800-61       ->  knowledge_source = "incident_response"

Usage (run from the project root, with the server STOPPED):
    python backend/scripts/ingest_sources.py --dry-run               # parse only, nothing is embedded
    python backend/scripts/ingest_sources.py --quick --recreate      # fast demo set (recommended first run)
    python backend/scripts/ingest_sources.py --recreate              # full MITRE ATT&CK (slower)
"""
import sys
import time
import logging
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.services.knowledge_sources import ALL_SOURCES, load_all  # noqa: E402  (no heavy imports)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("serc.ingest_sources")


def print_summary(sources: dict) -> int:
    total = 0
    print("\n" + "=" * 64)
    print("PARSE SUMMARY")
    print("=" * 64)
    for name in ALL_SOURCES:
        recs = sources.get(name, [])
        total += len(recs)
        docs = {r["incident_id"] for r in recs}
        sections = {}
        for r in recs:
            sections[r["section"]] = sections.get(r["section"], 0) + 1
        top = ", ".join(f"{k}:{v}" for k, v in sorted(sections.items(), key=lambda kv: -kv[1])[:6])
        print(f"\n[{name}]  chunks={len(recs)}  documents/IDs={len(docs)}")
        print(f"  sections: {top or '-'}")
        if recs:
            sample = recs[len(recs) // 2]
            print(f"  sample ({sample['chunk_id']}, {sample['source_reference']}):")
            print("    " + sample["chunk_text"][:300].replace("\n", "\n    "))
    print("\n" + "=" * 64)
    print(f"TOTAL chunks to ingest: {total}")
    print("=" * 64 + "\n")
    return total


def run(args) -> None:
    sources = load_all(Path(args.data_dir), quick=args.quick, include_rev2=args.include_rev2)
    total = print_summary(sources)

    if args.dry_run:
        print("Dry run only: nothing was embedded or written. Check the counts and samples above.")
        return
    if total == 0:
        logger.error("Nothing to ingest. Check the file names in %s", args.data_dir)
        return

    # Heavy imports only after parsing succeeded
    from backend.config import settings
    from backend.services.embedding_service import embedding_service
    from backend.services.retrieval_service import retrieval_service

    logger.info("Target collection: %s | embedding model: %s", settings.qdrant_collection, settings.embedding_model_name)
    retrieval_service.ensure_collection(recreate=args.recreate)

    start = time.time()
    done, failed = 0, 0
    for name in ALL_SOURCES:
        recs = sources.get(name, [])
        if not args.recreate:  # resume: skip chunks that are already stored
            have = retrieval_service.existing_chunk_ids([r["chunk_id"] for r in recs])
            if have:
                logger.info("[%s] %d chunks already stored, skipping them", name, len(have))
            recs = [r for r in recs if r["chunk_id"] not in have]
        for i in range(0, len(recs), args.batch_size):
            batch = recs[i:i + args.batch_size]
            try:
                vectors = embedding_service.embed_texts([r["search_text"] for r in batch], batch_size=args.batch_size)
                retrieval_service.upsert_batch(batch, vectors)
                done += len(batch)
            except Exception as exc:
                failed += len(batch)
                logger.error("Batch failed (%s, offset %d): %s", name, i, exc)
            logger.info("[%s] %d/%d chunks | overall %d/%d", name, min(i + args.batch_size, len(recs)), len(recs), done, total)

    stats = retrieval_service.get_stats()
    logger.info("=" * 64)
    logger.info("Done in %.1fs | ingested=%d failed=%d | vectors in Qdrant=%s", time.time() - start, done, failed, stats.get("total_vectors"))
    logger.info("=" * 64)
    retrieval_service.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Ingest official MITRE / NIST / incident-response sources into Qdrant")
    p.add_argument("--data-dir", default=str(PROJECT_ROOT / "data_sources"), help="Folder with the downloaded sources")
    p.add_argument("--quick", action="store_true", help="Only ~16 common ATT&CK techniques (fast demo set)")
    p.add_argument("--include-rev2", action="store_true", help="Also ingest the withdrawn NIST SP 800-61 Rev. 2 (overlaps Rev. 3)")
    p.add_argument("--dry-run", action="store_true", help="Parse and print a summary only; no embeddings, no Qdrant")
    p.add_argument("--recreate", action="store_true", help="Delete and rebuild the collection first")
    p.add_argument("--batch-size", type=int, default=32)
    run(p.parse_args())
