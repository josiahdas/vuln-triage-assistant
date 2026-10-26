# AI Vulnerability Triage Assistant

An LLM-powered pipeline that ingests live CVE data (NVD, EPSS, CISA KEV),
scores findings against a sample asset inventory using a composite risk
model, and generates grounded remediation recommendations via
retrieval-augmented generation (RAG) over vendor hardening guidance.

## Why this exists

Most vulnerability triage tools rank findings by CVSS alone, which measures
theoretical severity, not real-world risk. This project combines CVSS,
EPSS (exploit probability), CISA KEV (confirmed exploitation), and asset
context (internet exposure, business criticality) into a single risk score,
then uses an LLM grounded in vendor-specific hardening guidance to draft
an actual remediation recommendation — not just a priority number.

## Architecture

```
NVD / EPSS / CISA KEV APIs
        │
        ▼
  Ingestion pipeline (app/ingestion/)
        │
        ▼
  SQLite DB: Vulnerability, Asset, Finding (app/models.py)
        │
        ▼
  Risk scoring engine (app/risk/scoring.py)
        │
        ▼
  RAG retrieval over hardening guidance (app/rag/index.py, ChromaDB)
        │
        ▼
  LLM remediation generation (app/rag/triage.py, Claude API)
        │
        ▼
  FastAPI backend (app/api/main.py) ──► Streamlit dashboard (dashboard.py)
```

## Setup

1. **Clone and install dependencies:**
   ```bash
   python -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

2. **Get an Anthropic API key** at [console.anthropic.com](https://console.anthropic.com)
   (Settings → API Keys). This is separate from a claude.ai login and requires
   billing to be set up (usage for this project will cost cents, not dollars).

3. **Configure environment:**
   ```bash
   cp .env.example .env
   # edit .env and paste in your ANTHROPIC_API_KEY
   ```
   Optionally get a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
   for higher rate limits (works without one, just slower).

4. **Run the pipeline (from the project root):**
   ```bash
   # 1. Pull live CVE/EPSS/KEV data for the sample vendor scope
   python -m app.ingestion.pipeline

   # 2. Seed the sample asset inventory
   python -m app.seed_assets

   # 3. Match assets to CVEs and compute risk scores
   python -m app.risk.generate_findings

   # 4. Build the RAG index over hardening guidance
   python -m app.rag.index

   # 5. Run LLM triage on the top N highest-risk findings
   python -m app.risk.run_triage --limit 10
   ```

5. **Run the eval suite:**
   ```bash
   # Retrieval quality (no API cost) -- precision/hit-rate/MRR + a
   # content-level keyword check against a hand-labeled golden set
   python -m app.eval.retrieval_eval

   # Remediation quality: structural checks (free) + LLM-as-judge
   # scoring on groundedness and actionability (uses the API)
   python -m app.eval.remediation_eval --limit 10

   # Or run both at once:
   python -m app.eval.run_all
   ```
   Both evals are also exposed via the dashboard sidebar and the
   `/eval/retrieval` and `/eval/remediation` API endpoints.

6. **Run the app:**
   ```bash
   # Terminal 1: API backend
   uvicorn app.api.main:app --reload

   # Terminal 2: dashboard
   streamlit run dashboard.py
   ```
   Open http://localhost:8501 — the sidebar also has buttons to re-run
   ingestion/generation/triage directly from the UI.

7. **Run unit tests:**
   ```bash
   pytest tests/ -v
   ```

## Evaluation approach

- **Retrieval eval** (`app/eval/retrieval_eval.py`): a small hand-labeled
  golden set of (vendor, query) → expected source/keywords, scored with
  precision@k, hit-rate@k, and MRR. Because the current knowledge base has
  one document per vendor, file-level precision is trivially 1.0 once the
  vendor filter applies — that's flagged explicitly in the output rather
  than reported as a meaningful number. The keyword-hit-rate metric checks
  actual chunk content instead, which is the metric that would catch a
  real regression (e.g. retrieving the right file but the wrong section).
- **Remediation eval** (`app/eval/remediation_eval.py`): two layers —
  free structural checks (non-empty, reasonable length, includes the
  required priority-justification line, isn't generic filler) that run
  on every triaged finding with no API cost, and an LLM-as-judge pass
  that scores groundedness (does it stick to retrieved guidance rather
  than inventing vendor specifics?) and actionability (concrete step vs.
  generic advice) on a 1-5 scale.
- **Honest limitation**: the golden sets for both evals are small (7 and
  up to 10 items) and hand-written by the project author, not sourced
  from real triage outcomes. A production version would validate against
  actual analyst-labeled ground truth.

## Design decisions worth knowing (for interviews)

- **Risk formula** (`app/risk/scoring.py`): weighted combination of CVSS
  (severity), EPSS (exploit probability), a flat KEV bonus (confirmed
  exploitation is a stronger signal than a probability estimate), and
  multipliers for internet exposure and asset criticality. The weights are
  a documented starting point, not derived from data — a real next step
  would be validating them against historical incident data.
- **Asset matching** combines vendor+product string matching (not precise
  CPE version-range matching like production vulnerability scanners use)
  with a version-applicability heuristic (`app/risk/version_match.py`)
  that parses common NVD version-range phrasing to filter out CVEs that
  clearly don't apply to the asset's actual version. This heuristic was
  added *after* the eval harness caught the LLM inventing incorrect
  version-safety claims when asked to reason about version ranges from
  free text -- the fix was architectural (compute applicability
  deterministically, hand the LLM a verdict) rather than another prompt
  instruction, since the earlier prompt-only fix didn't fully hold up
  under eval. When the heuristic can't confidently resolve a version
  range, it returns "unknown" rather than guessing, and findings the
  heuristic scores as `not_affected` are filtered out during finding
  generation rather than surfaced to the LLM at all.
- **Embeddings** run locally via ChromaDB's default model (no API cost);
  a hosted embedding model would likely improve retrieval quality on a
  larger knowledge base.
- **Scope**: limited to four network/security vendors (Cisco, Palo Alto,
  Fortinet, Juniper) to keep the hardening knowledge base small and
  genuinely accurate rather than broad and shallow.

## Project structure

```
app/
  models.py              SQLAlchemy models (Vulnerability, Asset, Finding)
  db.py                  DB engine/session setup
  seed_assets.py          Sample asset inventory
  ingestion/
    fetch.py             NVD/EPSS/KEV API clients
    pipeline.py          Orchestrates ingestion + enrichment
  risk/
    scoring.py           Composite risk scoring engine
    version_match.py      Version-applicability heuristic (filters false-positive CVE/asset matches)
    generate_findings.py Joins assets to vulnerabilities, applies scoring
    run_triage.py         Batch LLM triage runner
  rag/
    index.py              Chunking + embedding + retrieval (ChromaDB)
    triage.py              LLM prompt construction + Claude API call
  api/
    main.py                FastAPI endpoints
  eval/
    retrieval_eval.py       Retrieval quality eval (golden set, precision/MRR)
    remediation_eval.py     Remediation quality eval (structural + LLM-as-judge)
    run_all.py               Runs both evals together
dashboard.py                Streamlit UI
tests/
  test_scoring.py          Unit tests for the risk model
data/
  knowledge_base/          Hardening guidance source docs (vendor-specific)
```
