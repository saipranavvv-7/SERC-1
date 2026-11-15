# SERC: Security Event Response Copilot

A web app that helps a security analyst understand a Wazuh alert. It finds relevant passages in official
sources (MITRE ATT&CK, NIST CSF 2.0, CERT-SG IRM playbooks, NIST SP 800-61), builds suggested next steps from them,
cites the source of every step, and checks every statement before showing how far it can be trusted.

It is based on the paper *Enhancing Security Operations Center: Wazuh Security Event Response with
Retrieval-Augmented-Generation-Driven Copilot* (Ismail et al., Sensors 2025, 25, 870, doi:10.3390/s25030870).
SERC re-creates its retrieval pipeline and adds an evidence validator, a human-approval step and flexible input.

## What is new compared with the paper

| Paper | This project |
|---|---|
| One alert shown with generated guidance | Every step carries a citation (E1, E2 ...) and links to the source passage |
| Quality measured offline against reference playbooks | Each statement is validated at runtime and labelled Supported, Partially supported, Conflicting, Not enough evidence or Needs review |
| No analyst control | Disruptive steps are flagged "needs analyst approval"; approvals and decisions are saved and exported |
| Wazuh JSON only | Wazuh JSON, pasted log lines, `.log` / `.txt` / `.csv` files, and screenshots (live mode) |
| Three collections | Three knowledge sources (MITRE, NIST, incident response) searched separately, de-duplicated and balanced |
| Needs LLM access | Works fully offline (every step is a sentence taken from a cited source); a live model is optional |
| No baseline without retrieval | A built-in RAG vs no-RAG comparison with the same checks on both answers (live mode) |

## How it works

1. **Input:** the alert is normalised into one Wazuh-style structure. Details guessed from plain text are shown for the analyst to confirm.
2. **Retrieval:** if the alert names a MITRE technique, its records are fetched directly; then each knowledge source is searched by meaning (BAAI/bge-large-en-v1.5, cosine similarity, Qdrant).
3. **Guidance:** offline mode picks action sentences from the retrieved passages. Live mode asks an LLM to write steps from the same passages and cite them.
4. **Validation:** facts must appear in the alert; MITRE mappings must come from the Wazuh rule or a retrieved record; steps must be grounded in the passage they cite; invented IP addresses, "is compromised" claims and citations of passages that were never retrieved are flagged.
5. **Analyst:** approves steps, accepts or rejects statements, asks follow-up questions, downloads a report.

## Setup (Windows, Python 3.10+)

1. Put the downloaded sources in `data_sources/`: `enterprise-attack.json`, `csf2.xlsx`, `NIST.SP.800-61r2.pdf` / `nist.sp.800-61r3.pdf`, and the CERT-SG `IRM` folder (PDFs).
2. `pip install -r backend/requirements.txt`
3. Copy `backend/.env.example` to `backend/.env`. Keep `QDRANT_PATH` **outside OneDrive**.
4. Check parsing without embedding anything: `python backend/scripts/ingest_sources.py --dry-run --quick`
5. Build the knowledge base (server stopped): `python backend/scripts/ingest_sources.py --quick --recreate`
   `--quick` ingests the techniques used by the sample alerts (about 1,130 passages; roughly 30 minutes on a laptop CPU). Without `--quick` it ingests all of ATT&CK (about 2,670 passages). Re-running without `--recreate` only adds what is missing, so you can run `--quick` first and the full set later.
6. `python backend/main.py`, then open http://127.0.0.1:8000

Only one program can use the embedded Qdrant folder at a time: stop the server before ingesting.

## Live mode with OpenAI (optional)

Offline mode needs nothing. To let GPT-4o write the guidance (which SERC then validates), read screenshots, and run the RAG vs no-RAG comparison:

1. Open `backend/.env` in an editor and set `MOCK_LLM_MODE=false` and `OPENAI_API_KEY=your key`. **Never paste the key into chat, a document or a public repository.** `.gitignore` already excludes `.env`.
2. In the OpenAI dashboard, set a monthly spending limit. A demo uses a few cents.
3. Run `python backend/scripts/check_llm.py`. It prints OK or the plain reason it failed (wrong key, no credit, wrong model name).
4. Restart the server. The header pill shows "Live model (gpt-4o)".

In live mode the alert text and the retrieved passages are sent to OpenAI. Do not use real production alerts you are not allowed to share. Screenshots are read by gpt-4o too, so no separate Mistral key is needed (a Pixtral key is used instead only if you set one).
If the live call fails for any reason, SERC falls back to offline guidance and says why.

## Using it

Paste an alert, upload a file or screenshot, or choose a sample. Check the details, press **Analyze**, then use the tabs:
Report, MITRE ATT&CK, Evidence, Verification and Ask a question. The "Technical details" switch shows scores and IDs.

## Knowledge sources (cite these)

| Source | Used for |
|---|---|
| MITRE ATT&CK Enterprise, STIX data (github.com/mitre-attack/attack-stix-data), **version 20.1** | Technique descriptions, mitigations and detection analytics |
| NIST Cybersecurity Framework 2.0, reference-tool export (csrc.nist.gov) | Functions, categories, subcategories, implementation examples |
| CERT Societe Generale, Incident Response Methodologies (github.com/certsocietegenerale/IRM); see its LICENSE | Incident-handling playbooks |
| NIST SP 800-61 Rev. 3 (Rev. 2 optional) | General incident-response guidance |

Downloaded 14 November 2026. Sample alerts in `backend/data/sample_alerts.json` are **synthetic** test input, not knowledge.

## What was learned by running it on the real data

Running all 55 sample alerts against the real parsed sources (not only small test data) exposed problems that were then fixed and covered by tests:

- ATT&CK v20.1 stores detection guidance as separate "detection strategies" and "analytics". SERC reads them and turns them into "Look for: ..." investigation steps.
- ATT&CK v20.1 **revoked some technique IDs that Wazuh rules still emit** (for example T1562.001, now T1685). SERC follows the replacement and says so. It also renamed tactics (Defense Evasion is now Stealth or Defense Impairment), so a tactic note is shown only when the alert's tactic is not listed by ATT&CK.
- The validator wrongly flagged 27 statements on real logs (quotes and backslashes in log text, the word "critical" in generic guidance, and "if the account is compromised" read as a declaration). All fixed.
- A low-severity alert with no ATT&CK mapping (for example a routine backup job) used to receive unrelated advice because search always returns something. It now only gets guidance that matches closely, otherwise none.
- Sample alert tactics and technique names were aligned with ATT&CK v20.1. Three samples keep the old revoked IDs on purpose, to show this behaviour.

## Limitations (please read)

- Validation shows whether a statement is **traceable** to the alert or a cited source. It does not prove the advice is correct or safe for a given environment. Grounding is a word-overlap check, not full semantic verification.
- Offline guidance is only as good as the retrieved passages. Weak matches are labelled, and the answer can be incomplete.
- In offline mode every step is a sentence from a cited source, so "wording matches the source" is true by design and the verification score is high. The score is most informative in live mode, where a model writes the text. What still varies offline is how closely a source matches the alert.
- Retrieval quality with the real embedding model (BAAI/bge-large-en-v1.5) was not measured here. `ROUTINE_MIN_SCORE` and `LOW_CONFIDENCE_THRESHOLD` are tunable and should be checked against real scores.
- Tested: all parsers on the real MITRE, NIST CSF and PDF files; the full pipeline on all 55 alerts; the UI in a real browser. Not tested here: FastAPI and Qdrant on your machine, the embedding model, and calls to the real OpenAI service. The live paths are tested against a simulated OpenAI (including models that reject some request settings), so the first real run is the real test: use `check_llm.py`.
- The paper's evaluation (cosine similarity and BERTScore against SOCFortress playbooks, 12 attack scenarios) was **not** reproduced here.
- Severity bands (Low, Medium, High, Critical) are SERC's own display labels, not an official Wazuh scale.
- Alerts are not sent anywhere in offline mode. In live mode, alert text and retrieved passages are sent to the configured provider.

## API

`GET /api/health` · `GET /api/alerts/samples` · `GET /api/alerts/samples/{id}` · `POST /api/alerts/ingest` · `POST /api/alerts/analyze` ·
`POST /api/alerts/chat` · `POST /api/feedback` · `GET /api/feedback/{alert_id}`. Interactive docs: http://127.0.0.1:8000/docs

## Tests

`python -m pytest tests -v` (or `python tests/test_serc.py`). They use an in-memory knowledge base built from your `csf2.xlsx`.
