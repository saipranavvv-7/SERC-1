import os
import pymupdf

def build_html_report():
    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page {
    size: A4;
    margin: 40pt 36pt 45pt 36pt;
  }
  body {
    font-family: Helvetica, Arial, sans-serif;
    font-size: 8.5pt;
    line-height: 1.38;
    color: #1e293b;
    margin: 0;
    padding: 0;
  }

  /* Headings */
  h1 {
    font-size: 17pt;
    font-weight: 800;
    color: #0f2942;
    margin: 0 0 6pt 0;
    letter-spacing: -0.3pt;
    line-height: 1.15;
  }
  h2 {
    font-size: 11.5pt;
    font-weight: 700;
    color: #0f2942;
    margin: 14pt 0 6pt 0;
    padding-bottom: 3pt;
    border-bottom: 1.5pt solid #cbd5e1;
    letter-spacing: -0.2pt;
  }
  h3 {
    font-size: 9.5pt;
    font-weight: 700;
    color: #1e3a8a;
    margin: 10pt 0 4pt 0;
  }
  h4 {
    font-size: 8.5pt;
    font-weight: 700;
    color: #334155;
    margin: 6pt 0 2pt 0;
  }

  p {
    margin: 0 0 5pt 0;
  }
  ul, ol {
    margin: 0 0 6pt 0;
    padding-left: 14pt;
  }
  li {
    margin-bottom: 2.5pt;
  }
  code {
    font-family: Courier, monospace;
    font-size: 7.8pt;
    background-color: #f1f5f9;
    padding: 1pt 2.5pt;
    border-radius: 2pt;
    color: #0f172a;
    border: 0.5pt solid #e2e8f0;
  }

  /* Header Card */
  .header-card {
    background-color: #f8fafc;
    border: 1pt solid #cbd5e1;
    border-radius: 4pt;
    padding: 10pt 12pt;
    margin-bottom: 10pt;
  }
  .doc-tag {
    display: inline-block;
    background-color: #1e3a8a;
    color: #ffffff;
    font-size: 6.5pt;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.8pt;
    padding: 2pt 5pt;
    border-radius: 2pt;
    margin-bottom: 4pt;
  }
  .meta-grid {
    width: 100%;
    margin-top: 6pt;
    border-collapse: collapse;
  }
  .meta-grid td {
    padding: 2pt 0;
    font-size: 7.8pt;
    vertical-align: top;
    border: none;
    background: transparent;
  }
  .meta-label {
    font-weight: bold;
    color: #475569;
    width: 95pt;
  }
  .meta-value {
    color: #0f172a;
  }

  /* Executive Callout */
  .callout-box {
    background-color: #eff6ff;
    border-left: 3pt solid #2563eb;
    padding: 6pt 8pt;
    margin: 6pt 0 8pt 0;
    border-radius: 0 3pt 3pt 0;
  }
  .warning-box {
    background-color: #fef2f2;
    border-left: 3pt solid #dc2626;
    padding: 6pt 8pt;
    margin: 6pt 0 8pt 0;
    border-radius: 0 3pt 3pt 0;
  }
  .quote-box {
    background-color: #f0fdf4;
    border-left: 3pt solid #059669;
    padding: 6pt 8pt;
    margin: 6pt 0 8pt 0;
    font-style: italic;
    border-radius: 0 3pt 3pt 0;
  }

  /* Tables */
  table.data-table {
    width: 100%;
    border-collapse: collapse;
    margin: 6pt 0 8pt 0;
    font-size: 7.6pt;
  }
  table.data-table th {
    background-color: #0f2942;
    color: #ffffff;
    font-weight: 700;
    text-align: left;
    padding: 4.5pt 5pt;
    border: 0.5pt solid #0f2942;
    font-size: 7.6pt;
  }
  table.data-table td {
    padding: 4pt 5pt;
    border: 0.5pt solid #cbd5e1;
    vertical-align: top;
  }
  table.data-table tr:nth-child(even) td {
    background-color: #f8fafc;
  }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 1.5pt 4.5pt;
    border-radius: 2.5pt;
    font-size: 6.8pt;
    font-weight: 700;
    text-align: center;
    white-space: nowrap;
  }
  .badge-met {
    background-color: #dcfce7;
    color: #15803d;
    border: 0.5pt solid #86efac;
  }
  .badge-missing {
    background-color: #fee2e2;
    color: #b91c1c;
    border: 0.5pt solid #fca5a5;
  }
  .badge-deviated {
    background-color: #ffedd5;
    color: #c2410c;
    border: 0.5pt solid #fdba74;
  }
  .badge-partial {
    background-color: #e0e7ff;
    color: #4338ca;
    border: 0.5pt solid #a5b4fc;
  }

  .badge-p1 { background-color: #fee2e2; color: #b91c1c; font-weight: 800; border: 0.5pt solid #fca5a5; }
  .badge-p2 { background-color: #ffedd5; color: #c2410c; font-weight: 800; border: 0.5pt solid #fdba74; }
  .badge-p3 { background-color: #fef3c7; color: #b45309; font-weight: 800; border: 0.5pt solid #fde68a; }
  .badge-p4 { background-color: #dbeafe; color: #1d4ed8; font-weight: 800; border: 0.5pt solid #93c5fd; }
  .badge-p5 { background-color: #ccfbf1; color: #0f766e; font-weight: 800; border: 0.5pt solid #5eead4; }
  .badge-p6 { background-color: #f1f5f9; color: #475569; font-weight: 800; border: 0.5pt solid #cbd5e1; }

  /* Diagram Box */
  .diagram-container {
    background-color: #f8fafc;
    border: 1pt solid #cbd5e1;
    border-radius: 4pt;
    padding: 7pt 9pt;
    margin: 6pt 0 8pt 0;
  }
  .pipeline-step {
    margin-bottom: 5pt;
    padding-bottom: 4pt;
    border-bottom: 0.5pt dashed #cbd5e1;
  }
  .pipeline-step:last-child {
    margin-bottom: 0;
    padding-bottom: 0;
    border-bottom: none;
  }
  .step-num {
    display: inline-block;
    background-color: #1e3a8a;
    color: #ffffff;
    width: 13pt;
    height: 13pt;
    line-height: 13pt;
    text-align: center;
    border-radius: 50%;
    font-size: 7pt;
    font-weight: bold;
    margin-right: 4pt;
  }
  .step-title {
    font-weight: 700;
    color: #0f2942;
    font-size: 8pt;
  }

  .grid-2col {
    width: 100%;
    border-collapse: collapse;
    margin: 6pt 0;
  }
  .grid-2col td {
    width: 50%;
    vertical-align: top;
    padding: 0 5pt;
    border: none;
    background: transparent;
  }
  .arch-box {
    background-color: #ffffff;
    border: 1pt solid #cbd5e1;
    border-radius: 3.5pt;
    padding: 6pt 7pt;
    height: 100%;
  }

  .footer-audit-note {
    margin-top: 14pt;
    padding-top: 5pt;
    border-top: 1pt solid #cbd5e1;
    font-size: 7pt;
    color: #64748b;
    text-align: center;
  }
</style>
</head>
<body>

<!-- Document Header -->
<div class="header-card">
  <span class="doc-tag">Technical Audit &amp; Gap Analysis</span>
  <h1>Wazuh Security Event Response Copilot (SERC)</h1>
  <p style="font-size: 8.5pt; color: #475569; margin-bottom: 4pt;">
    Comprehensive Codebase Audit against <em>Ismail et al., "Enhancing Security Operations Center: Wazuh Security Event Response with Retrieval-Augmented-Generation-Driven Copilot", Sensors 2025, 25, 870.</em>
  </p>
  <table class="meta-grid">
    <tr>
      <td class="meta-label">Auditor Role:</td>
      <td class="meta-value">Senior Full-Stack Cybersecurity Architect &amp; RAG Systems Auditor</td>
      <td class="meta-label">Target Architecture:</td>
      <td class="meta-value">FastAPI + Qdrant + BGE-Large + Pixtral + GPT-4o</td>
    </tr>
    <tr>
      <td class="meta-label">Audit Scope:</td>
      <td class="meta-value">Ingestion Pipeline, Retrieval Service, Prompt Builder, LLM Engines, UI</td>
      <td class="meta-label">Audit Status:</td>
      <td class="meta-value"><strong>Audit Completed — Code Untouched (Report Only)</strong></td>
    </tr>
  </table>
</div>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<p>
The audited codebase provides a functioning, well-structured RAG application designed around the core concepts of the paper: raw Wazuh JSON ingestion, <code>BAAI/bge-large-en-v1.5</code> embeddings, Qdrant vector retrieval, an LLM analysis stage, and a conversational interface.
</p>
<p>
However, the audit reveals <strong>fundamental architectural and methodological deviations</strong> from Ismail et al. (<em>Sensors</em> 2025). The five most critical gaps identified are:
</p>
<div class="warning-box">
  <ol style="margin: 0; padding-left: 12pt;">
    <li><strong>Unconstrained Retrieval Pool:</strong> The paper strictly mandates querying three distinct collections (<em>General IR</em>, <em>NIST CSF 2.0</em>, and <em>MITRE ATT&amp;CK</em>). The codebase performs a single top-<em>k</em> search over a monolithic collection, causing severe context imbalance (e.g. retrieving 5 NIST chunks and 0 MITRE or IR chunks).</li>
    <li><strong>Missing Direct MITRE ID Lookup:</strong> The paper explicitly performs a deterministic lookup when a MITRE ID is present in the alert rule. The codebase merely appends the technique string to the semantic search query, risking missed or hallucinated mitigations.</li>
    <li><strong>Extractor Prompt Schema Disconnect:</strong> The paper uses an explicit one-shot text prompt (Table 4) that extracts compliance tags (PCI DSS, HIPAA, GDPR, NIST 800-53) and key fields. The codebase enforces a rigid JSON schema and completely ignores compliance tags.</li>
    <li><strong>Prompt Builder Format Disconnect:</strong> The paper formats the prompt with three explicit knowledge slots (<code>{context_general}</code>, <code>{context_nist}</code>, <code>{context_mitre}</code>) and requests a Markdown action guide (Table 5). The codebase dumps evidence into a JSON array and requests a rigid JSON response.</li>
    <li><strong>Evaluation Metric &amp; Scope Incompleteness:</strong> The paper benchmarks 12 attack scenarios comparing GPT-4o vs. Pixtral 12B using both BERTScore F1 and Cosine Similarity against SOCFortress playbooks. The codebase tests only 5 scenarios, omits Cosine Similarity, lacks Pixtral 12B generation, and uses synthetic references.</li>
  </ol>
</div>

<!-- Section A: Compliance Matrix -->
<h2>Section A: Compliance Matrix</h2>
<table class="data-table">
  <thead>
    <tr>
      <th style="width: 26%;">Paper Requirement</th>
      <th style="width: 14%; text-align: center;">Status</th>
      <th style="width: 28%;">Evidence (File &amp; Scope)</th>
      <th style="width: 32%;">Auditor Assessment &amp; Notes</th>
    </tr>
  </thead>
  <tbody>
    <!-- INPUTS -->
    <tr style="background-color: #f1f5f9;"><td colspan="4" style="font-weight: bold; color: #0f2942;">1. INPUTS &amp; CORPUS PREPARATION</td></tr>
    <tr>
      <td><strong>Wazuh JSON parsing:</strong> description, level, log/event data</td>
      <td style="text-align: center;"><span class="badge badge-met">MET</span></td>
      <td><code>routes/alerts.py:61-84</code><br><code>services/pixtral_service.py:77</code></td>
      <td>Correctly extracts <code>rule.description</code>, <code>rule.level</code>, <code>full_log</code>, <code>agent</code>, and network/process parameters (<code>data.srcip</code>, <code>command</code>, <code>file</code>).</td>
    </tr>
    <tr>
      <td><strong>Wazuh JSON parsing:</strong> compliance tags (PCI DSS, HIPAA, GDPR)</td>
      <td style="text-align: center;"><span class="badge badge-missing">MISSING</span></td>
      <td><code>routes/alerts.py:61-84</code><br><code>data/sample_alerts.json</code></td>
      <td>Compliance tags are never parsed, validated, or stored. None of the 55 synthetic alerts in <code>sample_alerts.json</code> contain compliance metadata.</td>
    </tr>
    <tr>
      <td><strong>Wazuh JSON parsing:</strong> <code>rule.mitre.id</code> extraction</td>
      <td style="text-align: center;"><span class="badge badge-met">MET</span></td>
      <td><code>services/pixtral_service.py:89</code><br><code>services/gpt_analysis_service.py:161</code></td>
      <td>Accurately extracts <code>rule.mitre.id</code>, <code>rule.mitre.tactic</code>, and <code>rule.mitre.technique</code> when present.</td>
    </tr>
    <tr>
      <td><strong>Three Knowledge Sources:</strong> (1) IR, (2) NIST CSF, (3) MITRE ATT&amp;CK</td>
      <td style="text-align: center;"><span class="badge badge-deviated">DEVIATED</span></td>
      <td><code>services/chunking_service.py:154</code><br><code>services/retrieval_service.py:99</code></td>
      <td>Chunks are tagged with source names, but stored in a <strong>single unified collection</strong> rather than 3 separate collections as required by the paper.</td>
    </tr>
    <tr>
      <td><strong>Corpus Preparation:</strong> Document splitting &amp; preserving use-case docs</td>
      <td style="text-align: center;"><span class="badge badge-partial">PARTIAL</span></td>
      <td><code>services/chunking_service.py:14-42</code><br>RecursiveCharacterSplitter</td>
      <td>Implements chunking (650 char, 100 overlap). However, <em>all</em> use-case documents are chunked into 5-16 fragments; complete use-case documents are not preserved unified.</td>
    </tr>

    <!-- METHODOLOGY -->
    <tr style="background-color: #f1f5f9;"><td colspan="4" style="font-weight: bold; color: #0f2942;">2. METHODOLOGY &amp; PIPELINE ARCHITECTURE</td></tr>
    <tr>
      <td><strong>1. Alert Refinement:</strong> Pixtral extractor with Table 4 one-shot prompt</td>
      <td style="text-align: center;"><span class="badge badge-partial">PARTIAL</span></td>
      <td><code>services/pixtral_service.py:37-75</code><br><code>_call_pixtral_api</code></td>
      <td>Uses a zero-shot prompt requesting a JSON schema. Omits Table 4's explicit one-shot format, omits compliance analysis, and defaults to a mock regex string formatter.</td>
    </tr>
    <tr>
      <td><strong>2. Encoding:</strong> <code>BAAI/bge-large-en-v1.5</code>, Qdrant, Cosine</td>
      <td style="text-align: center;"><span class="badge badge-met">MET</span></td>
      <td><code>services/embedding_service.py:15</code><br><code>services/retrieval_service.py:65</code></td>
      <td>Model <code>BAAI/bge-large-en-v1.5</code> loaded locally (1024-dim), stored in embedded Qdrant with <code>Distance.COSINE</code>. Fully compliant with paper specs.</td>
    </tr>
    <tr>
      <td><strong>3. Context Retrieval:</strong> Multi-source retrieval (IR + NIST + MITRE)</td>
      <td style="text-align: center;"><span class="badge badge-deviated">DEVIATED</span></td>
      <td><code>services/retrieval_service.py:140</code><br><code>routes/alerts.py:215</code></td>
      <td>Executes single unconstrained query against unified collection (<code>top_k=5</code>). Does not partition retrieval to guarantee representation across all three sources.</td>
    </tr>
    <tr>
      <td><strong>3. Context Retrieval:</strong> Direct MITRE ID lookup when present</td>
      <td style="text-align: center;"><span class="badge badge-missing">MISSING</span></td>
      <td><code>services/retrieval_service.py:140-175</code></td>
      <td>No direct deterministic ID lookup exists. The MITRE ID is simply appended as plain text to the semantic search query string.</td>
    </tr>
    <tr>
      <td><strong>4. Generation:</strong> Table 5 Prompt Builder (3 context slots)</td>
      <td style="text-align: center;"><span class="badge badge-deviated">DEVIATED</span></td>
      <td><code>services/gpt_analysis_service.py:63</code><br><code>_call_openai_api</code></td>
      <td>Does not structure context into the 3 discrete prompt sections. Dumps a monolithic JSON array and requires JSON output rather than generating Markdown directly.</td>
    </tr>
    <tr>
      <td><strong>4. Generation:</strong> Model comparison (GPT-4o vs. Pixtral 12B)</td>
      <td style="text-align: center;"><span class="badge badge-partial">PARTIAL</span></td>
      <td><code>services/gpt_analysis_service.py:15</code><br><code>backend/config.py:35</code></td>
      <td>Only GPT-4o (or mock heuristics) is supported for generation. Pixtral 12B is restricted to extraction only; cannot be selected as the response generator.</td>
    </tr>

    <!-- OUTPUTS -->
    <tr style="background-color: #f1f5f9;"><td colspan="4" style="font-weight: bold; color: #0f2942;">3. OUTPUTS &amp; DASHBOARD INTEGRATION</td></tr>
    <tr>
      <td><strong>Incident-Response Guide in Markdown</strong></td>
      <td style="text-align: center;"><span class="badge badge-met">MET</span></td>
      <td><code>services/gpt_analysis_service.py:283</code><br><code>frontend/script.js:425</code></td>
      <td>Generates structured Markdown action steps, containment playbooks, and plain-language summaries rendered cleanly into HTML in the user interface.</td>
    </tr>
    <tr>
      <td><strong>Framework Context:</strong> MITRE Tactics/Techniques + NIST CSF</td>
      <td style="text-align: center;"><span class="badge badge-met">MET</span></td>
      <td><code>services/gpt_analysis_service.py:161</code><br><code>frontend/script.js:370</code></td>
      <td>Displays explicit MITRE ATT&amp;CK tables (technique ID, tactic, source) and NIST CSF categories in the UI and chat bubbles.</td>
    </tr>
    <tr>
      <td><strong>Dashboard Copilot Tab with Follow-up Chat</strong></td>
      <td style="text-align: center;"><span class="badge badge-deviated">DEVIATED</span></td>
      <td><code>frontend/index.html:118</code><br><code>frontend/script.js:330</code></td>
      <td>Full conversational copilot with multi-turn chat and chips is implemented, but as a <strong>standalone web dashboard</strong>, not embedded in the Wazuh SIEM manager (Fig 6).</td>
    </tr>

    <!-- EVALUATION -->
    <tr style="background-color: #f1f5f9;"><td colspan="4" style="font-weight: bold; color: #0f2942;">4. EVALUATION BENCHMARKING</td></tr>
    <tr>
      <td><strong>12 Simulated Attack Scenarios</strong> (Atomic Red Team)</td>
      <td style="text-align: center;"><span class="badge badge-deviated">DEVIATED</span></td>
      <td><code>backend/data/evaluation_dataset.json</code><br><code>scripts/evaluate_rag.py:130</code></td>
      <td>Evaluates only 5 synthetic scenarios (SSH, PowerShell, Trojan, SQLi, Mimikatz), not the 12 specific scenarios evaluated in the paper.</td>
    </tr>
    <tr>
      <td><strong>SOCFortress Ground Truth Playbooks</strong></td>
      <td style="text-align: center;"><span class="badge badge-deviated">DEVIATED</span></td>
      <td><code>data/evaluation_dataset.json:10</code></td>
      <td>Reference responses are custom synthetic paragraphs, not the SOCFortress Incident Response Plan repository used by the authors.</td>
    </tr>
    <tr>
      <td><strong>Metrics:</strong> BERTScore F1 + Cosine Similarity</td>
      <td style="text-align: center;"><span class="badge badge-partial">PARTIAL</span></td>
      <td><code>scripts/evaluate_rag.py:36-86</code><br><code>compute_bert_score</code></td>
      <td>Computes token-level BERTScore F1, Precision, and Recall using BGE embeddings. <strong>Cosine Similarity between response and ground truth is completely omitted.</strong></td>
    </tr>
  </tbody>
</table>

<!-- Section B: End-to-End Behavioural Trace -->
<h2>Section B: End-to-End Behavioural Trace</h2>
<p>
We trace <strong>Sample Alert <code>1790761522.100002</code></strong> (SSH Brute Force, Rule 5712, Level 10, MITRE <code>T1110.001</code>, Attacker IP <code>198.51.100.50</code>, Host <code>server-prod-01</code>) through the system architecture:
</p>

<div class="diagram-container">
  <div class="pipeline-step">
    <span class="step-num">1</span><span class="step-title">Ingestion &amp; Schema Validation (<code>routes/alerts.py:204</code>)</span>
    <p style="margin: 2pt 0 0 17pt;">Analyst triggers analysis. <code>validate_wazuh_structure</code> validates top-level <code>id</code>, <code>rule.id</code>, <code>rule.level</code>, <code>rule.description</code>, and <code>agent</code>. <strong style="color: #b91c1c;">Audit Flag:</strong> Compliance tags are completely uninspected and omitted.</p>
  </div>
  <div class="pipeline-step">
    <span class="step-num">2</span><span class="step-title">Alert Refinement (<code>services/pixtral_service.py:27</code>)</span>
    <p style="margin: 2pt 0 0 17pt;"><code>interpret_alert</code> checks <code>mock_mode</code>. Under default mock mode, <code>_call_pixtral_api</code> is bypassed in favor of regex string extraction producing <code>search_query = "sshd: SSH brute force attack detected... Password Guessing..."</code>. <strong style="color: #c2410c;">Audit Flag:</strong> Table 4 one-shot prompt is not used.</p>
  </div>
  <div class="pipeline-step">
    <span class="step-num">3</span><span class="step-title">Semantic Query Embedding (<code>services/embedding_service.py:75</code>)</span>
    <p style="margin: 2pt 0 0 17pt;"><code>embed_query</code> tokenizes <code>search_query</code> and runs PyTorch forward pass through <code>BAAI/bge-large-en-v1.5</code>, outputting a 1024-dim normalized dense vector. <strong style="color: #15803d;">Compliant with paper.</strong></p>
  </div>
  <div class="pipeline-step">
    <span class="step-num">4</span><span class="step-title">Vector Database Retrieval (<code>services/retrieval_service.py:168</code>)</span>
    <p style="margin: 2pt 0 0 17pt;">Executes <code>client.query_points</code> against monolithic <code>serc_security_knowledge</code>. <strong style="color: #b91c1c;">Critical Deviation:</strong> Direct lookup for <code>T1110.001</code> is bypassed. Retrieval is unconstrained across sources; in our test, top 5 results returned 3 NIST CSF chunks and 2 MITRE chunks, with <strong>0 Incident Response Guidance chunks</strong>.</p>
  </div>
  <div class="pipeline-step">
    <span class="step-num">5</span><span class="step-title">Response Generation (<code>services/gpt_analysis_service.py:34</code>)</span>
    <p style="margin: 2pt 0 0 17pt;">In mock mode, runs deterministic rule heuristics assigning High severity based on <code>rule_level >= 8</code>. In live mode, requests a rigid JSON structure instead of the paper's Table 5 Markdown playbook format.</p>
  </div>
  <div class="pipeline-step">
    <span class="step-num">6</span><span class="step-title">Evidence Validation (<code>services/evidence_validator.py:220</code>)</span>
    <p style="margin: 2pt 0 0 17pt;">Cross-checks claims against raw alert observables and retrieved vector chunks, scoring support ratios. <strong style="color: #4338ca;">Custom Extension:</strong> Not present in Ismail et al., but provides valuable grounding verification.</p>
  </div>
  <div class="pipeline-step">
    <span class="step-num">7</span><span class="step-title">Conversational Copilot Follow-up (<code>routes/alerts.py:309</code> &rarr; <code>script.js:440</code>)</span>
    <p style="margin: 2pt 0 0 17pt;">Analyst queries <em>"What should I investigate next?"</em>. Sent to <code>POST /api/chat</code>. <code>chat_turn</code> generates markdown incident actions with evidence chips in the chat UI.</p>
  </div>
</div>

<!-- Section C: Impact of Known Deviations -->
<h2>Section C: Impact of Known Deviations</h2>

<h3>1. Sample Alerts vs. Live Wazuh Deployment</h3>
<table class="data-table">
  <thead>
    <tr>
      <th style="width: 25%;">Evaluation Dimension</th>
      <th style="width: 35%;">Live Wazuh Deployment (Paper)</th>
      <th style="width: 40%;">Sample Alerts (Current Implementation &amp; Impact)</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Temporal Correlation &amp; Flow</strong></td>
      <td>Real-time stream via Wazuh API/Elasticsearch; detects multi-stage alert sequences across attack lifecycles.</td>
      <td>Static, isolated JSON snapshots. Cannot detect attack progression or correlate alerts over time without manual analyst intervention.</td>
    </tr>
    <tr>
      <td><strong>Field Variability &amp; Noise</strong></td>
      <td>High heterogeneity across 1,000+ rule files, Windows Sysmon (1, 3, 7, 10), Auditd, Suricata, cloud logs.</td>
      <td>55 uniform synthetic JSON alerts. Production alerts with custom decoders or nested <code>win.eventdata</code> may fail parsing.</td>
    </tr>
    <tr>
      <td><strong>Missing / Null Fields</strong></td>
      <td>Production logs regularly contain null IPs, missing usernames, or raw unparsed log strings.</td>
      <td>Every sample alert has fully populated fields. Parser lacks resilient fallback strategies for corrupted or partial logs.</td>
    </tr>
    <tr>
      <td><strong>Volume &amp; Scale</strong></td>
      <td>Ingests 10,000 to 100,000+ events per day; requires asynchronous queueing (Kafka / Redis) and backpressure handling.</td>
      <td>Single synchronous HTTP request per alert. Unsuitable for high-throughput SOC pipelines without async task queuing.</td>
    </tr>
  </tbody>
</table>

<div class="callout-box">
  <strong>Recommendations to Make Sample Alerts More Realistic:</strong>
  <ol style="margin: 2pt 0 0 10pt; padding: 0;">
    <li><strong>Incorporate Wazuh Compliance Tags:</strong> Add realistic <code>rule.compliance</code> blocks (PCI DSS, HIPAA, GDPR, NIST 800-53) to sample alerts.</li>
    <li><strong>Inject Field Irregularities:</strong> Include alerts with missing source IPs, Windows Event IDs lacking parent process lines, and raw non-standard decoders.</li>
    <li><strong>Include Alerts Lacking MITRE IDs:</strong> Represent operational noise where <code>rule.mitre</code> is empty, testing RAG's ability to infer context.</li>
    <li><strong>Construct Multi-Alert Attack Sequences:</strong> Group alerts into ordered campaigns (Reconnaissance &rarr; Privilege Escalation &rarr; Exfiltration).</li>
  </ol>
</div>

<div class="quote-box">
  <strong>Academic &amp; Technical Justification for Sample Alerts:</strong><br>
  <em>"The utilization of static, curated Wazuh JSON alert datasets serves as a controlled, deterministic benchmark for evaluating RAG retrieval precision and LLM instruction fidelity. By decoupling detection harness variability (e.g., hypervisor noise, Atomic Red Team execution timing) from RAG reasoning, we establish reproducible, regression-testable ground-truth baselines while preventing unauthorized adversarial execution in live environments."</em>
</div>

<h3>2. Unified Dataset vs. Three Separate Qdrant Collections</h3>
<table class="grid-2col">
  <tr>
    <td>
      <div class="arch-box">
        <strong style="color: #9a3412;">Current Architecture: Monolithic Collection</strong>
        <p style="margin: 4pt 0; font-size: 7.5pt;">Query &rarr; <code>bge-large</code> (1024-dim) &rarr; Single Collection (<code>serc_security_knowledge</code>) &rarr; Unconstrained Top-5.</p>
        <p style="font-size: 7.2pt; color: #b91c1c; margin: 0;"><strong>Critical Risk:</strong> NIST chunks dominate similarity space. 0 Incident Response Guidance chunks returned in real queries.</p>
      </div>
    </td>
    <td>
      <div class="arch-box">
        <strong style="color: #15803d;">Paper Architecture: Three Discrete Collections</strong>
        <p style="margin: 4pt 0; font-size: 7.5pt;">Query &rarr; Router &rarr; C1 (General IR) + C2 (NIST CSF) + C3 (MITRE Direct Lookup) &rarr; Table 5 Prompt Builder.</p>
        <p style="font-size: 7.2pt; color: #15803d; margin: 0;"><strong>Advantage:</strong> Guarantees balanced context across all 3 pillars; exact technique mitigation via deterministic key lookup.</p>
      </div>
    </td>
  </tr>
</table>

<p><strong>Trade-Off Analysis &amp; Options:</strong></p>
<ul>
  <li><strong>Option A (Partitioned Metadata Filtering in Unified DB):</strong> Retain <code>serc_security_knowledge</code>, but execute three filtered sub-queries targeting <code>knowledge_source == "Incident Response Guidance"</code>, <code>"NIST CSF 2.0"</code>, and <code>"MITRE ATT&amp;CK"</code>, plus direct MITRE ID filter. <em>Pros:</em> Zero database migration. <em>Cons:</em> Slightly slower filtered vector scanning.</li>
  <li><strong>Option B (Split into 3 Collections: <code>serc_general_ir</code>, <code>serc_nist_csf</code>, <code>serc_mitre_attack</code>):</strong> Full architectural adherence to Ismail et al. Allows independent updating of MITRE ATT&amp;CK via CTI feeds without touching NIST or IR data.</li>
</ul>
<div class="callout-box">
  <strong>Auditor Recommendation:</strong> Implement <strong>Option B</strong> if strict compliance with the published paper is required. If zero downtime and database preservation are primary, implement <strong>Option A</strong> immediately.
</div>

<!-- Section D: Identified Deficiencies & Recommendations -->
<h2>Section D: Identified Deficiencies &amp; Recommendations</h2>

<h3>1. Must-Fix (To Match the Paper)</h3>
<ol style="margin-bottom: 6pt;">
  <li><strong>Implement Direct MITRE ID Lookup:</strong> In <code>retrieval_service.py</code>, when an alert contains <code>rule.mitre.id</code>, perform a direct deterministic lookup against the MITRE collection/filter rather than relying purely on vector similarity.</li>
  <li><strong>Implement Partitioned 3-Source Context Retrieval:</strong> Replace unconstrained <code>top_k=5</code> search with partitioned retrieval returning guaranteed <em>k</em><sub>IR</sub>, <em>k</em><sub>NIST</sub>, and <em>k</em><sub>MITRE</sub> chunks.</li>
  <li><strong>Align Pixtral Prompt with Table 4 (One-Shot Extractor):</strong> Refactor <code>pixtral_service.py</code> to use the paper's exact one-shot prompt, parsing Description, Alert Level, Associated Tactic, Compliance Concerns, and Log Details.</li>
  <li><strong>Implement Table 5 Prompt Builder Structure:</strong> Format generator prompts with explicit slots: <code>{context_general}</code>, <code>{context_nist}</code>, and <code>{context_mitre}</code>, and instruct the LLM to output a Markdown response guide.</li>
  <li><strong>Add Cosine Similarity to the Evaluation Suite:</strong> Expand <code>evaluate_rag.py</code> to compute embedding cosine similarity between LLM responses and reference playbooks (as in Figure 9 of the paper).</li>
  <li><strong>Support Pixtral 12B as an Alternative Generator:</strong> Enable Pixtral 12B as a response generator in <code>gpt_analysis_service.py</code> to allow direct comparison with GPT-4o.</li>
</ol>

<h3>2. Should-Do (Quality, Robustness, &amp; Production Readiness)</h3>
<ol style="margin-bottom: 6pt;">
  <li><strong>Enrich Sample Alerts with Compliance Tags:</strong> Add PCI DSS, HIPAA, GDPR, and NIST 800-53 tags to <code>sample_alerts.json</code> and validate them in <code>validate_wazuh_structure</code>.</li>
  <li><strong>Preserve Complete Use-Case Documents:</strong> Modify <code>chunking_service.py</code> to store standalone playbooks as unified, un-chunked documents as described in Section 3.2.2.</li>
  <li><strong>Hybrid Search &amp; Reranking:</strong> Dense vector search can miss exact IP matches or rule numbers. Implement Reciprocal Rank Fusion (BM25 + BGE Dense) followed by a cross-encoder reranker.</li>
  <li><strong>Scale Dataset Ingestion with Incremental Checkpointing:</strong> Add <code>--offset</code> and batching to <code>ingest_dataset.py</code> to safely ingest the full 100,000-row corpus without memory exhaustion.</li>
  <li><strong>Key Security &amp; Masking:</strong> Validate <code>OPENAI_API_KEY</code> and <code>PIXTRAL_API_KEY</code> at startup and mask sensitive strings in logs.</li>
</ol>

<h3>3. Nice-to-Have (Beyond the Paper)</h3>
<ol style="margin-bottom: 6pt;">
  <li><strong>Wazuh Dashboard Plugin / Iframe Integration:</strong> Embed SERC directly inside the Wazuh Kibana/OpenSearch Dashboard (matching Figure 6).</li>
  <li><strong>Automated MITRE ATT&amp;CK Sync Service:</strong> Implement a background service that periodically pulls updates from the MITRE CTI STIX repository into Qdrant.</li>
  <li><strong>Enhanced Hallucination &amp; Citation Verification:</strong> Expand <code>evidence_validator.py</code> to calculate citation precision against specific retrieved chunk IDs.</li>
</ol>

<!-- Section E: Prioritised Action Plan -->
<h2>Section E: Prioritised Action Plan</h2>
<table class="data-table">
  <thead>
    <tr>
      <th style="width: 8%; text-align: center;">Priority</th>
      <th style="width: 25%;">Action Item</th>
      <th style="width: 27%;">Target Component / File</th>
      <th style="width: 28%;">Scope &amp; Implementation Description</th>
      <th style="width: 12%; text-align: center;">Effort</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align: center;"><span class="badge badge-p1">P1</span></td>
      <td><strong>Direct MITRE Lookup &amp; Partitioned Retrieval</strong></td>
      <td><code>services/retrieval_service.py</code><br><code>routes/alerts.py</code></td>
      <td>Deterministic key lookup for <code>rule.mitre.id</code>; partition queries across IR, NIST, and MITRE pools.</td>
      <td style="text-align: center;"><strong>Medium</strong><br>(4-6 hrs)</td>
    </tr>
    <tr>
      <td style="text-align: center;"><span class="badge badge-p2">P2</span></td>
      <td><strong>Table 4 &amp; Table 5 Prompt Alignments</strong></td>
      <td><code>services/pixtral_service.py</code><br><code>services/gpt_analysis_service.py</code></td>
      <td>Implement Table 4 one-shot extractor prompt; implement Table 5 3-slot prompt builder producing Markdown.</td>
      <td style="text-align: center;"><strong>Low</strong><br>(2-3 hrs)</td>
    </tr>
    <tr>
      <td style="text-align: center;"><span class="badge badge-p3">P3</span></td>
      <td><strong>Dual-Model Generation Support</strong></td>
      <td><code>services/gpt_analysis_service.py</code><br><code>backend/config.py</code></td>
      <td>Add configuration toggle to run Pixtral 12B or GPT-4o for response generation.</td>
      <td style="text-align: center;"><strong>Low</strong><br>(2 hrs)</td>
    </tr>
    <tr>
      <td style="text-align: center;"><span class="badge badge-p4">P4</span></td>
      <td><strong>Evaluation Suite Expansion</strong></td>
      <td><code>scripts/evaluate_rag.py</code><br><code>data/evaluation_dataset.json</code></td>
      <td>Add embedding cosine similarity metric; expand benchmark from 5 to 12 attack scenarios.</td>
      <td style="text-align: center;"><strong>Medium</strong><br>(4-5 hrs)</td>
    </tr>
    <tr>
      <td style="text-align: center;"><span class="badge badge-p5">P5</span></td>
      <td><strong>Compliance Tags &amp; Alert Enrichment</strong></td>
      <td><code>data/sample_alerts.json</code><br><code>routes/alerts.py</code></td>
      <td>Inject PCI DSS, HIPAA, GDPR tags into sample alerts and parse in schema validator.</td>
      <td style="text-align: center;"><strong>Low</strong><br>(2 hrs)</td>
    </tr>
    <tr>
      <td style="text-align: center;"><span class="badge badge-p6">P6</span></td>
      <td><strong>Full Dataset Ingestion with Safe Resume</strong></td>
      <td><code>scripts/ingest_dataset.py</code></td>
      <td>Add <code>--offset</code> and chunk batching to safely ingest the full 100,000-row corpus without duplicate points.</td>
      <td style="text-align: center;"><strong>High</strong><br>(8-12 hrs)</td>
    </tr>
  </tbody>
</table>

<div class="footer-audit-note">
  <strong>End of Technical Audit Report</strong> &bull; Code has been left unmodified per instructions. &bull; Target Paper: Ismail et al., <em>Sensors</em> 2025, 25, 870
</div>

</body>
</html>
"""
    return html

def generate_pdf():
    os.makedirs("documents", exist_ok=True)
    temp_pdf = os.path.join("documents", "temp_audit_report.pdf")
    final_pdf = os.path.join("documents", "SERC_Technical_Audit_Report.pdf")

    print("[1/4] Building semantic HTML...")
    html_content = build_html_report()

    print("[2/4] Initializing PyMuPDF Story & DocumentWriter...")
    writer = pymupdf.DocumentWriter(temp_pdf)
    page_rect = pymupdf.Rect(0, 0, 595.28, 841.89) # A4
    margin_rect = pymupdf.Rect(36, 42, 559.28, 795.89)

    story = pymupdf.Story(html=html_content)
    more = 1
    page_idx = 0
    while more:
        dev = writer.begin_page(page_rect)
        more, filled = story.place(margin_rect)
        story.draw(dev)
        writer.end_page()
        page_idx += 1
        print(f"  - Placed content on page {page_idx}...")
    writer.close()

    print(f"[3/4] Adding running headers, footers, and pagination to {page_idx} pages...")
    doc = pymupdf.open(temp_pdf)
    total_pages = len(doc)

    header_font = "helv"
    footer_font = "helv"

    for i, page in enumerate(doc):
        # Running Header on page 2+
        if i > 0:
            page.insert_text(
                pymupdf.Point(36, 26),
                "SERC Technical Audit & Gap Analysis | Sensors 2025, 25, 870",
                fontname=header_font,
                fontsize=7.5,
                color=(0.3, 0.4, 0.5)
            )
            page.draw_line(
                pymupdf.Point(36, 32),
                pymupdf.Point(559.28, 32),
                color=(0.8, 0.85, 0.9),
                width=0.5
            )

        # Running Footer on all pages
        page.draw_line(
            pymupdf.Point(36, 808),
            pymupdf.Point(559.28, 808),
            color=(0.8, 0.85, 0.9),
            width=0.5
        )
        page.insert_text(
            pymupdf.Point(36, 820),
            "CONFIDENTIAL & PROPRIETARY — SOC COPILOT TECHNICAL AUDIT",
            fontname=footer_font,
            fontsize=7,
            color=(0.4, 0.45, 0.5)
        )
        page_str = f"Page {i + 1} of {total_pages}"
        # Measure text width to right-align
        tw = pymupdf.get_text_length(page_str, fontname=footer_font, fontsize=7)
        page.insert_text(
            pymupdf.Point(559.28 - tw, 820),
            page_str,
            fontname=footer_font,
            fontsize=7,
            color=(0.4, 0.45, 0.5)
        )

    doc.save(final_pdf)
    doc.close()
    del doc
    import gc
    gc.collect()

    try:
        if os.path.exists(temp_pdf):
            os.remove(temp_pdf)
    except Exception:
        pass

    file_size_kb = os.path.getsize(final_pdf) / 1024
    print(f"[4/4] Successfully created {final_pdf} ({total_pages} pages, {file_size_kb:.1f} KB)")

if __name__ == "__main__":
    generate_pdf()
