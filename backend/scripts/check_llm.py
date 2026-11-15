"""
Checks that live mode works, using the key in backend/.env. Run from the project root:
    python backend/scripts/check_llm.py
It sends one tiny request and prints OK or a plain reason for the failure. The key is never printed.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import settings  # noqa: E402
from backend.services.llm_client import LLMClient, describe_error  # noqa: E402

llm = LLMClient(settings)
print(f"MOCK_LLM_MODE = {settings.mock_llm_mode}   OPENAI_MODEL = {settings.openai_model}   key set: {bool(settings.openai_api_key)}")
if settings.mock_llm_mode:
    sys.exit("Live mode is off. Set MOCK_LLM_MODE=false in backend/.env, then run this again.")
if not settings.openai_api_key:
    sys.exit("No key found. Add OPENAI_API_KEY=... to backend/.env (the file, not the chat).")
try:
    reply = llm.complete_text("Reply with the single word OK.", "ping")
    print("OK: the model answered:", reply.strip()[:40])
except Exception as exc:
    sys.exit(f"FAILED: {describe_error(exc)}")
