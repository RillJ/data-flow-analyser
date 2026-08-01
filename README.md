# Beyond the Banner: AI-Powered Network Traffic Analysis for Privacy Risk Detection

`data-flow-analyser` is an open-source, AI-assisted command-line tool for analysing captured HTTP(S) traffic from privacy-testing scenarios. It is designed to support technical privacy assessments and Data Protection Impact Assessments (DPIAs) by making observed data flows easier to inspect, classify, and compare with vendor documentation.

The tool analyses what a service actually sends over the network. It does not replace a privacy expert or make definitive legal determinations. Its output is an evidence-based risk map for human verification.

## Research context

Technical privacy assessments often depend on manual inspection of large mitmproxy or HAR-derived datasets. However, generic network-security tools do not provide enough privacy-specific automation. This project aims to improve the efficiency, reproducibility, and transparency of technical privacy research used in DPIAs.

The central research question is:

> How can an AI-based open-source tool automate the analysis of network traffic data, generated from privacy testing scenarios, to efficiently identify and assess privacy risks within the context of DPIAs?

The current implementation contributes to that question by combining deterministic traffic analysis with LLM-assisted document extraction and cross-referencing. The deterministic stages preserve technical evidence; the LLM is used to interpret structured evidence against policy claims.

## Current capabilities

### Network-flow parsing

- Reads mitmproxy flow-dump files and HAR files.
- Converts HAR entries to temporary mitmproxy flows automatically, so HAR captures use the same analysis path and do not create sidecar files.
- Converts HTTP flows into a common `NetworkFlow` schema.
- Extracts URLs, query paths, request and response headers, request and response bodies, timestamps, status codes, and cookies.
- Recursively decodes JSON, Base64, and URL-encoded payloads where possible.
- Skips unsupported or malformed flows with diagnostic logging.


### Personal data flow and identifier detection

Identifying which data is sent to which endpoint helps reviewers connect observed technical behaviour to privacy risks, policy claims, and possible international transfers. The deterministic detectors preserve the underlying traffic evidence, while the AI-assisted stages help organise and compare that evidence with the supplied policy documents.

#### Seed matching
Optional seed values can be supplied through a JSON file. For each seed, the analyser generates plaintext, case variants, MD5, SHA-1, SHA-256, and Base64 lookup values. It scans request and response URLs, headers, bodies, and cookies, including recursively decoded JSON, URL-encoded, and Base64-wrapped payloads.

The seed values are useful for controlled privacy testing scenarios. For example, a test email address or account identifier entered during a browser interaction. Raw matched values should be treated as sensitive evidence. Matches are grouped by endpoint, direction, payload location, data label, and detection method. The JSON report retains occurrence counts, matched values, and source flow IDs for reproduction; the LLM and Markdown report receive/show the compact grouped evidence.

#### Named Entity Recognition and Regular Expression matching
When installed, the optional Presidio integration discovers the available Presidio recognisers dynamically instead of using a short hard-coded entity list. It scans global entity types such as names, email addresses, phone numbers, locations, dates, IP addresses, URLs, MAC addresses, crypto wallets, IBANs, and credit cards, together with configured European country-specific recognisers. The European profile includes the Netherlands (`NL`) alongside the UK, Spain, Italy, Poland, Finland, Sweden, Germany, and Turkey; Presidio may not provide a built-in recogniser for every country. Non-European country-specific recognisers are excluded by default.

Presidio results are candidates rather than proof. For performance, very large network flows use a separate deterministic-only Presidio analyser without spaCy NER. Use `--presidio-full-ner` to use the full NER on all values, but note that these can be substantially slower.

If Presidio or its spaCy model is unavailable, the seed-based pipeline continues and records an analysis warning.

#### Shannon entropy calculations
The analyser also calculates Shannon character entropy for candidate strings. Values that are at least eight characters long and meet the default entropy threshold of `3.5` are reported as possible dynamic identifiers. Generic HTTP negotiation headers such as `Accept` and `Accept-Language` are excluded because their values can score highly without being identifiers. Entropy evidence is grouped by endpoint and payload location before it is sent to the LLM, using counts, reuse, flow count, and entropy ranges rather than raw token strings. Entropy is a heuristic supporting signal, meaning a high score does not prove that a value is personal data or a tracker.

### Endpoint profiling

For each observed host, the tool can:

- Resolve the hostname to an IP address.
- Perform reverse-DNS lookup.
- Look up country and ASN/organisation metadata.
- Check the DuckDuckGo Tracker Radar, including parent-domain suffix matches.
- Record tracker category, parent entity, third-country-transfer indicators, and lookup results.

Network and external lookup failures are retained as diagnostic events rather than silently treated as confirmed facts.

### Cookies and storage

The storage profiler inventories observed cookie names from sent and set cookies, then compares them with storage items extracted from the supplied policy documents. It reports:

- Documented cookies.
- Undocumented cookies.
- Cookies with excessive lifetimes.
- Observed lifespan and matching policy declarations.
- The network hosts where each cookie was observed being set or sent.
- The optional `Domain=` attribute declared in `Set-Cookie` headers.

Cookies with a parsed lifetime longer than 90 days are flagged by the rule-based analyser. This is an analytical threshold, not a legal conclusion.

### Browser and device fingerprinting candidates

The analyser looks for bundled fingerprinting attributes across:

- URL query parameters.
- Selected request headers and client hints, such as `User-Agent`, `Accept-Language`, viewport, device-memory, and `Sec-CH-UA-*` headers.
- Recursively decoded JSON and form-like request bodies.

The current taxonomy includes display, locale/time, hardware/OS, canvas, audio, WebGL, and system-capability signals. A request becomes a fingerprinting candidate when it bundles multiple relevant categories, with additional weight for canvas, audio, or WebGL signals.

This is an explainable attribute-co-occurrence heuristic. It does not claim a measured number of uniqueness bits because that requires an external population-frequency baseline. The current version also does not generate synthetic browser variations or run browser automation.

### Consent-phase analysis

Consent metadata is optional because not every capture contains pre-consent, consented, and withdrawn phases. When timestamps are supplied, flows are assigned to phases using their capture timestamps:

- `pre_consent`
- `consented`
- `withdrawn`
- `unknown`

If timestamps are omitted, the tool does **not** assume that consent was denied. All flows remain `unknown` for consent-phase analysis.

Identical fingerprint candidates observed in consented and withdrawn phases are reported as persistence findings. Missing phase data is reported as unknown; it is not treated as proof of compliance or non-compliance.

### Policy analysis and LLM cross-referencing

The document ingestor sends the complete aggregated policy/DPA text by default to an LLM and extracts:

- Declared personal-data categories.
- Declared subprocessors.
- Declared cookies and storage mechanisms.
- International-transfer mechanisms.
- Retention statements.

The cross-referencer then receives structured policy claims together with observed endpoints, grouped personal-data flow mappings, grouped identifier signals, cookie results, and fingerprint evidence. It produces endpoint classifications, storage classifications, and discrepancy cards with reasoning and policy citations where available.

### Indicative risk evaluation

Discrepancy risk is evaluated using a deterministic likelihood-and-severity method informed by GDPR Recital 75 and based on the [Information Commissioner's Office (UK ICO) DPIA method](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/accountability-and-governance/data-protection-impact-assessments-dpias/how-do-we-do-a-dpia#how10). The LLM identifies relevant potential harms and provides the factual basis for two inputs; the application calculates the score and indicative level. This prevents the LLM from freely choosing the final risk category.

The harm assessment considers physical, material, and non-material damage, including:

- Discrimination, identity theft or fraud, and financial loss.
- Reputational damage and loss of confidentiality.
- Unauthorised reversal of pseudonymisation.
- Significant economic or social disadvantage.
- Loss of control over personal data or inability to exercise rights.
- Special-category data and criminal-conviction data.
- Profiling of personal aspects such as interests, behaviour, health, economic situation, location, or movements.
- Data concerning vulnerable people, particularly children.
- Large-scale processing affecting many data subjects.

Likelihood and severity use three levels:

| Score | Likelihood of harm | Severity of impact |
| ---: | --- | --- |
| 1 | Remote | Minimal impact |
| 2 | Reasonable possibility | Some impact |
| 3 | More likely than not | Serious harm |

The risk score is `likelihood × severity`. The indicative matrix is:

| Likelihood \\ Severity | 1 | 2 | 3 |
| --- | --- | --- | --- |
| 1 | Low | Low | Low |
| 2 | Low | Medium | High |
| 3 | Low | High | High |

These levels are indications for human review, not definitive legal conclusions. The Markdown and JSON reports include the inputs, score, indicative level, potential harms, assessment basis, and a human-verification flag.

LLM classifications are validated after parsing. Unknown classifications, omitted observed endpoints, invalid evidence references, deterministic storage overrides, and incomplete risk inputs are recorded as report warnings. Evidence references may identify flow IDs, observed endpoint domains or IPs, grouped personal-data mappings, grouped entropy signals, observed storage items, or fingerprint vectors. A report with such warnings has `analysis_status: partial`; an execution or parsing failure has `analysis_status: failed`.

### Reproducibility

Every JSON report records the tool version, model, temperature, analysis timestamps, reference time, and SHA-256 hashes of the capture, policy documents, and seed data. Seed data are hashed rather than copied into provenance metadata. Cookie expiry calculations use the flow timestamp or the recorded analysis reference time; when neither is available, an absolute `Expires` directive is reported as having unknown lifespan instead of using the current wall-clock time.

For research runs, retain the capture, policy-document versions, seed-file version, generated JSON report, generated Markdown report, and verbose log together. External DNS, GeoIP, reverse-DNS, and Tracker Radar results remain time-dependent; use cached or locally snapshotted metadata when exact replay is required.

### Debugging

With `--verbose`, the exact system and user prompts sent to both LLM calls are written to the console. With `--log-file`, they can be retained for reproducibility. Because these prompts can contain complete policy documents and traffic-derived values, log files must be protected as sensitive research data.

## Installation

The project requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

For seed-independent personal-data detection, install the spaCy model matching the language you want to analyse. For Dutch:

```bash
python -m spacy download nl_core_news_lg
```

See the [spaCy model documentation](https://spacy.io/models/nl) for model details.

The core pipeline remains usable without the model. Presidio findings are then skipped and reported as an analysis warning. The CLI defaults to English (`--presidio-language en`); use a matching spaCy model and language option for supported European languages such as Dutch (`nl`), German (`de`), Spanish (`es`), Italian (`it`), or French (`fr`).

Supported models:
- en_core_web_lg
- nl_core_news_lg
- de_core_news_lg
- es_core_news_lg
- it_core_news_lg
- fr_core_news_lg

The package uses LiteLLM for model access. Configure the provider credentials expected by LiteLLM in `.env`, or provide `--api-key` and optionally `--api-base` on the command line.

## Usage

### Check the installation

Check that the installation is available:

```bash
data-flow-analyser healthcheck
```

### Review endpoints before an audit

Before an audit, use the deterministic endpoint inventory command to review every host in a capture. It does not call an LLM or enrich domains over the network:

```bash
data-flow-analyser endpoints \
  --capture scenarios.flows \
  --out-json endpoints.json
```

The inventory includes flow counts, methods, paths, and first/last observation times. Use it to create an optional exclusion file for browser, Mozilla, extension, or other researcher-identified traffic:

```json
{
  "domains": [
    "mozilla.org",
    "bitwarden.com"
  ]
}
```

Pass that file to `audit` with `--exclude-file`. Matching is case-insensitive and excludes the listed domain plus all of its subdomains. Excluded flows are removed immediately after parsing, before endpoint profiling, seed matching, cookie and identifier analysis, fingerprint analysis, or LLM cross-referencing. Without `--exclude-file`, no flows are excluded.

```bash
data-flow-analyser audit \
  --capture scenarios.flows \
  --doc dpa.txt \
  --exclude-file excluded-domains.json
```

### Run an audit

Run an audit with one or more policy documents, for example:

```bash
data-flow-analyser audit \
  --capture scenarios.flows \
  --doc dpa.txt \
  --doc cookies.rst \
  --out-json audit.json \
  --out-md audit.md
```

### Match controlled test values

Add controlled seed values from a JSON file:

```json
{
  "email": "research-user@example.org",
  "account_id": "test-account-123"
}
```

```bash
data-flow-analyser audit \
  --capture scenarios.flows \
  --doc dpa.txt \
  --seed-file seed.json
```

### Control reproducibility

The LLM temperature can be set explicitly for a run:

```bash
data-flow-analyser audit \
  --capture scenarios.flows \
  --doc dpa.txt \
  --temperature 0
```

### Analyse consent phases

Provide consent-event timestamps when the capture contains those phases. Timestamps must be ISO-8601 and include a timezone:

```bash
data-flow-analyser audit \
  --capture scenarios.flows \
  --doc dpa.txt \
  --consent-granted-at "2026-06-28T10:15:00+02:00" \
  --consent-withdrawn-at "2026-06-28T10:40:00+02:00"
```

### Enable diagnostics

Use verbose diagnostics to inspect every major processing stage and the exact LLM inputs:

```bash
data-flow-analyser audit \
  --capture scenarios.flows \
  --doc dpa.txt \
  --verbose \
  --log-file audit-debug.log
```

### Use full Presidio NER

By default, Presidio uses fast deterministic recognisers for very large values to avoid running spaCy NER over entire response bodies. To use the full NER on those values as well, use `--presidio-full-ner`.

```bash
data-flow-analyser audit \
  --capture scenarios.flows \
  --doc dpa.txt \
  --presidio-full-ner \
  --verbose
```

### Understand the reports

Every audit writes both a JSON report and a Markdown report, and always prints the Markdown report to the terminal. Use `--out-json` and/or `--out-md` to choose explicit output paths. If omitted, both files are written to the current directory as `audit-YYYYMMDD-HHMMSS.json` and `audit-YYYYMMDD-HHMMSS.md`.

## Processing pipeline

```mermaid
flowchart TD
    A["Capture\nmitm flows · HAR"] --> B["Parse and normalise flows"]
    R["Policy documents"]

    subgraph DET["Deterministic analysis"]
        B --> C["<b>Decode payload values</b>\nRecursive JSON · Base64 · URL decoding"]
        B --> D["<b>Match supplied seeds</b>\nPlaintext + case variants · MD5 · SHA-1 · SHA-256 · Base64"]
        B --> F["<b>Analyse identifiers</b>\nGrouped entropy and cookie lifetime evidence"]
        B --> G["<b>Detect fingerprint vectors</b>\nQuery · headers · decoded bodies"]
        B --> H["<b>Profile endpoints</b>\nDNS · GeoIP · ASN · DDG Tracker Radar"]
        D --> I["<b>Grouped personal-data flow mapping</b>"]
        F --> J["<b>Technical evidence summary</b>"]
        G --> J
        H --> J
        I --> J
    end

    subgraph AI["AI-assisted analysis"]
        C --> E["<b>Presidio personal data detection</b>\nNER + regex"]
        E --> I
        K["<b>Extract policy claims</b>\nLLM document analysis"]
        K --> L["<b>Personal data processing claims</b>"]
        J --> M["<b>Cross-reference audit</b>\nValidating technical evidence against policy claims"]
        L --> M
        M --> N["<b>Discrepancy evidence</b>\nPolicy comparisons and citations"]
        N --> O["<b>LLM risk evaluation</b>\n Harm categories and likelihood/severity inputs"]
    end

    R --> K

    subgraph OUT["Human-verifiable output"]
        O --> P["<b>Deterministic risk evaluator</b>\nLikelihood × severity · fixed matrix"]
        P --> Q["<b>JSON and Markdown reports</b>"]
    end

    classDef input fill:#e8f1ff,stroke:#356ae6,color:#123;
    classDef analysis fill:#eef9f0,stroke:#3b8f52,color:#132;
    classDef model fill:#fff4df,stroke:#c77b16,color:#321;
    classDef output fill:#f3eaff,stroke:#7a45b5,color:#231;

    class A,R input;
    class B,C,D,F,G,H,I,J analysis;
    class E,K,L,M,N,O model;
    class P,Q output;
```

## Development and testing

Run the test suite from the project virtual environment:

```bash
.venv/bin/python -m pytest -q
```

The test suite covers decoding, entropy and cookie-lifetime analysis, seed matching, endpoint profiling, document ingestion, cross-referencing, pipeline execution, fingerprint-vector/consent-phase analysis, and the deterministic ICO-style risk evaluator.

For reproducible research, retain the capture file, policy-document versions, seed-file version, consent timestamps, model/provider configuration, verbose logfile, and generated JSON report together. External endpoint metadata should also be treated as time-dependent evidence.

## Project structure

```text
src/data_flow_analyser/
├── cli.py                         Command-line interface and logging setup
├── endpoint_inventory.py          Domain exclusion and endpoint helpers
├── exporter.py                    JSON and Markdown report generation
├── pipeline.py                    End-to-end orchestration
├── models/
│   ├── __init__.py
│   └── schemas.py                 Shared flow, evidence, and report schemas
├── parsers/
│   ├── __init__.py
│   ├── har_converter.py            HAR-to-mitmproxy conversion
│   ├── mitm_parser.py              mitmproxy flow and HAR parsing
│   └── decoder.py                  Recursive payload decoding
├── engines/
│   ├── __init__.py
│   ├── cross_referencer.py         LLM evidence cross-reference and parsing
│   ├── document_ingestor.py        LLM policy extraction
│   ├── endpoint_profiler.py        DNS, GeoIP, ASN, and Tracker Radar metadata
│   ├── entropy.py                  Grouped identifier and cookie-lifetime analysis
│   ├── fingerprint_profiler.py     Fingerprint vector and consent-phase analysis
│   ├── presidio_detector.py        Seed-independent PII candidate detection
│   ├── risk_evaluator.py           Deterministic likelihood/severity scoring
│   ├── seed_hasher.py              Controlled-value and encoded/hash matching
│   └── storage_profiler.py         Deterministic cookie/policy reconciliation
└── __init__.py                     Package metadata
```

## License and research use

This project is licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE) for the attribution notice.

The project is intended as an open-source research and assessment aid. Before analysing real traffic, confirm that the capture, policy documents, seed values, and any third-party lookups may be processed in the environment. Generated reports and verbose log files may contain personal, confidential, or security-sensitive information and should be handled accordingly.
