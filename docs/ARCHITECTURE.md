# 🏗️ Architecture Documentation

## Overview

Blue Team Assistant is built with a modular, pipeline-based architecture that allows for easy extension and customization. This document explains the core components and how they interact.

---

## Core Principles

### 1. Separation of Concerns
Each module has a single responsibility:
- **Tools**: Orchestrate analysis workflows
- **Analyzers**: Perform specific file type analysis
- **Integrations**: Connect to external services
- **Scoring**: Calculate threat levels
- **Reporting**: Generate output formats

### 2. Data-Driven Decisions
All verdicts are based on:
- Threat intelligence API responses
- Static analysis findings
- Behavioral indicators

AI/LLM is used only for **interpretation**, never for **decision making**.

### 3. Fail-Safe Behavior
- Missing API keys = reduced functionality, not failure
- Network timeouts = graceful degradation
- Unknown file types = generic analysis
- Optional integrations are initialized on a best-effort basis; failures are logged and dependent functionality degrades gracefully.

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ENTRY POINTS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │   CLI            │    │   MCP Server     │    │   Direct Import  │      │
│  │   soc_agent.py   │    │   server.py      │    │   Python API     │      │
│  └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘      │
│           │                       │                       │                 │
│           └───────────────────────┼───────────────────────┘                 │
│                                   ▼                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                              ANALYSIS TOOLS                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         IOCInvestigator                              │   │
│  │  ├── Input: IP, Domain, URL, Hash                                   │   │
│  │  ├── Process: Query 20+ TI sources                                  │   │
│  │  └── Output: Verdict + Sources + Rules                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         MalwareAnalyzer                              │   │
│  │  ├── Input: File path                                               │   │
│  │  ├── Process: Type detection → Static analysis → TI lookup          │   │
│  │  └── Output: Verdict + Indicators + Rules + MITRE mapping           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         EmailAnalyzer                                │   │
│  │  ├── Input: .eml or .msg file                                       │   │
│  │  ├── Process: Header analysis → URL extraction → Attachment scan   │   │
│  │  └── Output: Verdict + Phishing indicators + IOCs                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### IOC Investigation Flow

```
┌──────────┐     ┌────────────────┐     ┌─────────────────┐     ┌──────────┐
│  Input   │────▶│  IOC Extractor │────▶│  ThreatIntel    │────▶│ Scoring  │
│  IOC     │     │  (categorize)  │     │  (20+ sources)  │     │          │
└──────────┘     └────────────────┘     └─────────────────┘     └────┬─────┘
                                                                      │
                        ┌─────────────────────────────────────────────┘
                        ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Rule Generator │────▶│  LLM Analyzer   │────▶│  Report         │
│  (YARA/SIGMA)   │     │  (interpret)    │     │  Generator      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

### Malware Analysis Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          MALWARE ANALYSIS PIPELINE                            │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STAGE 1: File Identification                                                │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  FileTypeRouter                                                        │ │
│  │  ├── Magic bytes detection                                             │ │
│  │  ├── Extension validation                                              │ │
│  │  └── Route to appropriate analyzer                                     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STAGE 2: Hash Reputation                                                    │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ThreatIntelligence.investigate_hash()                                 │ │
│  │  ├── VirusTotal lookup                                                 │ │
│  │  ├── MalwareBazaar check                                               │ │
│  │  ├── Hybrid Analysis search                                            │ │
│  │  └── Triage search                                                     │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STAGE 3: Static Analysis                                                    │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Type-Specific Analyzer (PE/ELF/Office/PDF/Script)                     │ │
│  │  ├── Header parsing                                                    │ │
│  │  ├── Section analysis                                                  │ │
│  │  ├── Import/Export extraction                                          │ │
│  │  ├── String extraction                                                 │ │
│  │  └── Entropy calculation                                               │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STAGE 4: Deep Analysis                                                      │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  EntropyAnalyzer    : Packing/encryption detection                     │ │
│  │  StringExtractor    : IOC extraction from strings                      │ │
│  │  YARAScanner        : Pattern matching                                 │ │
│  │  MITREMapper        : Technique identification                         │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                              │                                               │
│                              ▼                                               │
│  STAGE 5: Scoring & Output                                                   │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  ToolBasedScoring   : Aggregate all signals                            │ │
│  │  RuleGenerator      : Create detection rules                           │ │
│  │  HTMLReportGenerator: Generate HTML report                             │ │
│  │  SOCOutputFormatter : Generate CLI output                              │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Descriptions

### tools/

#### `ioc_investigator.py`
Main orchestrator for IOC analysis.

```python
class IOCInvestigator:
    def __init__(self, config: Dict):
        self.threat_intel = ThreatIntelligence(config)
        self.llm_analyzer = LLMAnalyzer(config)
    
    async def investigate(self, ioc: str) -> Dict:
        # 1. Categorize IOC type
        # 2. Check trusted infrastructure whitelist
        # 3. Query threat intelligence sources
        # 4. Calculate threat score
        # 5. Generate detection rules
        # 6. Return comprehensive result
```

#### `malware_analyzer.py`
Main orchestrator for file analysis.

```python
class MalwareAnalyzer:
    def __init__(self, config: Dict):
        self.file_router = FileTypeRouter()
        self.pe_analyzer = PEAnalyzer()
        self.threat_intel = ThreatIntelligence(config)
        # ... more analyzers
    
    async def analyze(self, file_path: str) -> Dict:
        # 1. Detect file type
        # 2. Check hash reputation
        # 3. Run type-specific analyzer
        # 4. Calculate entropy
        # 5. Extract strings and IOCs
        # 6. Scan with YARA
        # 7. Map to MITRE ATT&CK
        # 8. Calculate final score
        # 9. Generate rules and report
```

### analyzers/

#### `pe_analyzer.py`
Windows PE file analysis using pefile.

**Extracted Data:**
- Headers (DOS, NT, Optional)
- Sections (name, entropy, characteristics)
- Imports/Exports
- Resources
- Signatures
- Security features (ASLR, DEP, CFG)

#### `elf_analyzer.py`
Linux ELF binary analysis.

**Extracted Data:**
- ELF header
- Program headers
- Section headers
- Symbol table
- Dynamic linking

#### `office_analyzer.py`
Microsoft Office document analysis using oletools.

**Extracted Data:**
- VBA macros
- OLE streams
- Embedded objects
- Suspicious patterns

### integrations/

#### `threat_intel.py`
Core threat intelligence integration.

**Sources:**
- VirusTotal (file/URL/IP/domain)
- AbuseIPDB (IP reputation)
- Shodan (IP data)
- AlienVault OTX (pulses)
- URLhaus (malicious URLs)
- ThreatFox (IOCs)
- MalwareBazaar (samples)

#### `threat_intel_extended.py`
Extended sources for comprehensive coverage.

**Additional Sources:**
- GreyNoise (scanner detection)
- Censys (certificate data)
- IPQualityScore (fraud detection)
- Hybrid Analysis (sandbox)
- Triage (sandbox)
- ANY.RUN (sandbox)
- Joe Sandbox (sandbox)

#### `llm_analyzer.py`
Local LLM integration via Ollama.

**Usage:**
- Interpret technical findings
- Generate natural language summaries
- Explain MITRE techniques
- **NOT for decision making**

### scoring/

#### `intelligent_scoring.py`
Multi-signal threat scoring algorithm.

The current application IOC-scoring formula uses an explicit admission policy
with AHP-derived source-specific multipliers. The six sources admitted by the
formula are `feodotracker`, `c2_trackers`, `spamhaus`, `tor_exit_nodes`,
`sslblacklist`, and `threatfox`. This scoring-source list is implemented by
`NON_API_SCORING_SOURCES` and `SOURCE_SCORING_MULTIPLIERS` in
`src/scoring/intelligent_scoring.py`; it is separate from
`GROUP_A_EVAL_SOURCES`, which is evaluation configuration. VirusTotal and
other API/query sources remain report-only. Source availability (`clean`,
`unavailable`, and `stale`) is tracked separately and unavailable must not be
interpreted as clean. The derivation is documented in
`docs/source_weight_ahp_derivation_2026-09-16.md`.

```python
# Current application IOC-scoring admission and source-specific multipliers.
# This is an
# abridged excerpt; the complete AHP derivation is documented in
# docs/source_weight_ahp_derivation_2026-09-16.md.
from src.scoring.intelligent_scoring import (
    NON_API_SCORING_SOURCES,
    SOURCE_SCORING_MULTIPLIERS,
)

class IntelligentScoring:
    @staticmethod
    def calculate_ioc_score(intel_results: Dict) -> int:
        sources = intel_results.get('sources', {})
        weighted_scores = []
        for source, result in sources.items():
            source_name = source.lower()
            if source_name not in NON_API_SCORING_SOURCES:
                continue
            if not isinstance(result, dict) or result.get('unavailable'):
                continue
            source_score = IntelligentScoring._get_source_score(result)
            if source_score > 0:
                weighted_scores.append(
                    source_score * SOURCE_SCORING_MULTIPLIERS[source_name]
                )
        # The application implementation applies the documented multi-source
        # boost before clamping 0-100. Domain-age/DGA enrichment remains
        # analyst-facing metadata/recommendation context, not score input.
        return max(0, min(100, int(sum(weighted_scores) / len(weighted_scores))))
```

The score formula consumes admitted IOC-source results only. Domain-age,
DGA, and LLM-DGA enrichment remain outside this score formula and are exposed
as enrichment or interpretation context.

#### `false_positive_filter.py`
Reduces false positives through:
- Trusted infrastructure whitelist
- Known good software detection
- Signature validation
- Prevalence checking

### detection/

#### `rule_generator.py`
Generates detection rules from analysis results.

**Formats:**
- YARA (file scanning)
- SIGMA (log detection)
- KQL (Microsoft Defender)
- SPL (Splunk)

---

## Configuration

### config.yaml Structure

```yaml
# API Keys
api_keys:
  virustotal: ""
  abuseipdb: ""
  shodan: ""
  alienvault: ""
  hybrid_analysis: ""
  greynoise: ""
  urlscan: ""

# LLM Configuration
llm:
  provider: "ollama"    # ollama, openai, anthropic
  model: "llama3.2:3b"
  api_key: ""
  base_url: "http://localhost:11434"

# Analysis Settings
analysis:
  max_file_size_mb: 100
  timeout_seconds: 300
  enable_sandbox: true
  enable_yara: true
  enable_llm: true

# Output Settings
output:
  default_format: "cli"  # cli, json, html
  save_reports: true
  report_dir: "./reports"
```

## Configuration and Application Lifecycle

The web factory configures authenticated page/API access and registers
ticketing, agent storage, MCP, notification, Gmail OAuth, correlation,
memory, and route-level authorization components. It attempts to initialize
optional runtime components on a best-effort basis. If an optional component
cannot be initialized, the failure is logged and dependent functionality
degrades gracefully; dependent routes may return `503` as described under
Fail-Safe Behavior.

`CorrelationEngine` and `InvestigationMemory` are initialized by
`src/web/app.py:create_app` when available. The correlation engine is consumed
by `/api/agent/correlation/{session_id}`. Investigation memory is consumed by
`/api/agent/memory/ioc/{ioc}` and `/api/agent/memory/stats`.

---

## Extending the System

### Adding a New File Analyzer

1. Create `src/analyzers/new_analyzer.py`:

```python
class NewAnalyzer:
    def analyze(self, file_path: str) -> Dict:
        return {
            'file_type': 'new_type',
            'analysis': {...}
        }
```

2. Register in `file_type_router.py`:

```python
self.analyzers['new_type'] = NewAnalyzer()
```

3. Add to `malware_analyzer.py`:

```python
if file_type == 'new_type':
    result = self.new_analyzer.analyze(file_path)
```

### Adding a New TI Source

1. Add method in `threat_intel_extended.py`:

```python
async def check_new_source(self, ioc: str) -> Dict:
    # API call implementation
    return {
        'source': 'NewSource',
        'found': True/False,
        'data': {...}
    }
```

2. Complete the admission and AHP review before adding a source to application
   IOC scoring. The source must be added to the explicit
   `SOURCE_SCORING_MULTIPLIERS`/`NON_API_SCORING_SOURCES` policy with a
   documented derivation; do not assign an arbitrary integer weight:

```python
# See docs/source_weight_ahp_derivation_2026-09-16.md for the required
# evidence, pairwise comparison, priority vector, and multiplier mapping.
```

---

## Performance Considerations

### Async Architecture
All network operations use `asyncio` for non-blocking I/O:
- Parallel API calls
- Timeout handling
- Graceful degradation

### Caching
Future enhancement: Add caching layer for:
- TI API responses
- File hashes
- Analysis results

### Rate Limiting
Built-in availability handling:
- Source-specific API/query limits remain constraints for report-only sources
- ThreatFox uses the 15-second production deadline; timeout means unavailable,
  no retry, no pipeline block, and exclusion from that round's score
- Unavailable results are never interpreted as clean

---

## Security Considerations

### Authentication and Authorization
- Browser pages are protected by `PageAuthMiddleware`.
- Protected API routes use `get_current_user`; selected routers/routes also
  apply `require_role(...)`.
- Resource ownership and visibility checks are route-specific; this document
  does not claim that every route has identical authorization behavior.
- Human approval checks apply to selected agent actions, not universally to
  every route.

### API Key Storage
- Keys stored in `config.yaml`
- File should have restricted permissions
- Never commit to version control

### Input Validation
- File size limits
- Type validation
- Path traversal prevention

### Output Sanitization
- HTML escaping in reports
- No arbitrary code execution
- Safe string handling
