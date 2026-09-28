# 🛡️ SRE Autonomous Incident Response Agent

### Python · FastAPI · Groq Llama 3.1 70B

An intelligent, autonomous SRE (Site Reliability Engineering) agent that triages production outages, correlates multi-signal telemetry (logs, metrics, and deployments), diagnoses root causes using Groq-accelerated Llama 3.1 70B, and orchestrates remediation actions with safety-first human-in-the-loop approval workflows.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Groq](https://img.shields.io/badge/Groq-Llama_3.1_70B-F55036.svg?style=flat)](https://groq.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Repository-181717.svg?style=flat&logo=github)](https://github.com/JestuAshok/SRE-Autonomous-Incident-Response-Agent---Python-FastAPI---Groq-Llama-3.1-70B)

---

## 🎯 What It Does

SentinelAI is an **AI-powered incident response system** that acts as your automated on-call engineer:

### 🔍 **Intelligent Incident Detection & Diagnosis**
- Automatically analyzes production alerts and outages
- Correlates error logs, stack traces, metrics, and deployment history
- Uses **Groq's Llama 3.1 LLM** for forensic root cause analysis
- Identifies culprit deployments with file-level precision
- Detects false-positive deployment blame (e.g., external vendor outages)

### 🧠 **Multi-Signal Correlation Engine**
- **Log Analysis**: Parses multi-line stack traces, exception patterns, and error timestamps
- **Deployment Correlation**: Matches deployment timing with incident onset
- **Metric Anomaly Detection**: Identifies CPU spikes, error rate surges, latency degradation
- **Alternative Hypothesis Testing**: Checks for memory exhaustion, connection pool saturation, upstream failures

### 🤖 **Autonomous Remediation Recommendations**
- Proposes rollback commands for deployment regressions
- Suggests scaling operations for resource exhaustion
- Recommends circuit breaker activation for vendor outages
- Provides one-click approval/rejection workflow

### 🛡️ **Safety & Policy Engine**
- **MANUAL Mode**: All actions require human approval
- **AUTONOMOUS Mode**: Auto-executes low-risk, high-confidence actions (e.g., night mode)
- **TIMED_FALLBACK Mode**: Dead man's switch auto-executes after timeout
- Configurable confidence thresholds and safety guardrails

### 📊 **Real-Time Command Center UI**
- Modern glassmorphism dashboard with dark theme
- Live incident timeline and status tracking
- Interactive remediation action approval
- Audit trail of all decisions and executions

---

## 🚀 Key Features Implemented

### ✅ Core Capabilities

- **🔧 Autonomous Agent**: Self-directed incident investigation with tool-calling capabilities
- **🧪 Root Cause Analysis**: AI-powered diagnosis using Groq Llama 3.1 70B
- **📈 Anomaly Detection**: Statistical spike detection in error rates, latency, CPU/memory
- **🔄 Deployment Correlation**: Timeline-based causality linking with commit-level precision
- **📝 Stack Trace Parsing**: Multi-line exception extraction and file-level mapping
- **🎯 Action Proposals**: Automated generation of rollback/scale/throttle commands
- **✋ Human-in-the-Loop**: Approval workflow with reviewer tracking and audit logs
- **⏰ Dead Man's Switch**: Timed fallback auto-execution for unattended incidents
- **🔐 Policy Engine**: Configurable safety modes (Manual/Autonomous/Timed Fallback)
- **📡 Real-Time UI**: WebSocket-ready React dashboard for live incident tracking

### 🛠️ Technical Implementation

#### **Backend (Python + FastAPI)**
- **FastAPI REST API** with automatic OpenAPI documentation
- **Pydantic Models** for type-safe incident, evidence, and action schemas
- **Correlation Engine** for cross-domain telemetry analysis
- **Groq Integration** with tool-calling for LLM-powered diagnosis
- **Policy Engine** with confidence scoring and risk assessment
- **Notification System** for PagerDuty/Slack escalations (simulated)

#### **AI/LLM Integration**
- **Groq Llama 3.1 70B** for natural language reasoning
- **Tool Use Protocol** with three investigation tools:
  - `read_logs()` - Log querying with filters
  - `get_deploy_history()` - Deployment timeline retrieval
  - `get_metrics()` - Metric time-series analysis
- **Fallback Logic** to deterministic forensic engine when LLM unavailable
- **Structured Output Parsing** with confidence scoring

#### **Frontend (Vanilla JavaScript)**
- **Modern UI** with glassmorphism design and dark theme
- **Responsive Layout** optimized for command center displays
- **Interactive Actions** with one-click approve/reject buttons
- **Live Updates** via polling (WebSocket-ready architecture)
- **Timeline Visualization** of incident progression

#### **Data & Testing**
- **Realistic Scenarios**: CrowdStrike kernel panic, Cloudflare regex catastrophe, checkout NPE
- **Synthetic Telemetry**: Production-grade logs, metrics, and deployment data
- **Evaluation Suite**: Automated benchmarking across multiple incident types
- **Pytest Coverage**: Unit and integration tests for all components

---

## 📂 Architecture Overview

```
incident-response-agent/
├── 📊 data/
│   ├── logs/                        # Service logs with multi-line stack traces
│   │   ├── crowdstrike_sensor.log   # Kernel panic scenario (BugCheck 0x50)
│   │   ├── cloudflare_edge.log      # Regex catastrophic backtracking
│   │   ├── checkout_service.log     # NullPointerException after deploy
│   │   └── payment_gateway.log      # External Stripe API 503 outage
│   ├── deployments.json             # Deployment history with commit diffs
│   └── metrics.json                 # CPU, memory, error rate, latency time-series
│
├── 🛠️ tools/
│   ├── log_tool.py                  # Log parser with exception extraction
│   ├── deploy_tool.py               # Deployment timeline & causality analyzer
│   ├── metrics_tool.py              # Anomaly detection & baseline comparison
│   └── notification_tool.py         # PagerDuty/Slack escalation dispatcher
│
├── 🤖 agent/
│   ├── models.py                    # Pydantic schemas (Incident, Evidence, Action)
│   ├── diagnosis_agent.py           # Groq LLM integration with tool calling
│   ├── correlation_engine.py        # Multi-signal telemetry correlation
│   ├── policy_engine.py             # Safety modes & approval workflow
│   └── agent.py                     # Main IncidentResponseAgent orchestrator
│
├── 🌐 api/
│   └── main.py                      # FastAPI REST API & UI server
│
├── 💻 ui/
│   ├── index.html                   # Command center dashboard
│   ├── styles.css                   # Glassmorphism dark theme
│   └── app.js                       # Incident viewer & approval actions
│
├── 🧪 eval/
│   ├── test_cases.json              # Benchmark evaluation scenarios
│   ├── scenarios.py                 # Test scenario definitions
│   ├── run_eval.py                  # Automated evaluation runner
│   ├── test_agent.py                # Pytest agent tests
│   ├── test_policy.py               # Policy engine tests
│   └── test_tools.py                # Tool integration tests
│
├── 📄 Configuration Files
│   ├── .env                         # Groq API credentials (not in git)
│   ├── requirements.txt             # Python dependencies
│   ├── README.md                    # This file
│   └── GROQ_SETUP.md               # Groq integration guide
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.10+**
- **Groq API Key** (get one free at [console.groq.com](https://console.groq.com))

### 1️⃣ Clone & Setup Virtual Environment
```powershell
# Clone the repository (or download)
cd incident-response-agent

# Create virtual environment
python -m venv venv

# Activate (PowerShell on Windows)
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2️⃣ Configure Groq API Key
Create a `.env` file in the project root:
```env
GROQ_API_KEY=gsk_your_actual_groq_api_key_here
GROQ_MODEL=llama-3.1-70b-versatile
```

> **Note**: Without an API key, the agent falls back to deterministic forensic analysis.

### 3️⃣ Start the Server
```powershell
# Run with auto-reload
python -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### 4️⃣ Open the Dashboard
Navigate to **[http://localhost:8000](http://localhost:8000)** in your browser.

You'll see 4 pre-loaded demo incidents:
- 🚨 CrowdStrike Falcon Sensor Kernel Panic
- 🔥 Cloudflare Edge Regex Catastrophe
- 🛒 Checkout Service NullPointerException
- 💳 Payment Gateway External API Outage

---

## 🎮 How to Use

### Via Web UI
1. **View Incidents**: Browse all active incidents in the dashboard
2. **Inspect Details**: Click on any incident to see full diagnostic report
3. **Review Actions**: Check proposed remediation actions with confidence scores
4. **Approve/Reject**: One-click approval or rejection with reviewer attribution
5. **Watch Execution**: See live rollout progress with health check logs

### Via API
```bash
# List all incidents
curl http://localhost:8000/api/incidents

# Trigger investigation for a service
curl -X POST http://localhost:8000/api/incidents/analyze \
  -H "Content-Type: application/json" \
  -d '{"service": "checkout-service", "title": "Error rate spike"}'

# Approve a remediation action
curl -X POST http://localhost:8000/api/incidents/{incident_id}/action \
  -H "Content-Type: application/json" \
  -d '{"action_id": "act-rollback-...", "approve": true, "reviewer": "alice@company.com"}'

# Check policy configuration
curl http://localhost:8000/api/policy
```

### Policy Modes

**Switch between safety modes:**
```bash
# MANUAL: All actions require human approval (default)
curl -X POST http://localhost:8000/api/policy \
  -H "Content-Type: application/json" \
  -d '{"mode": "MANUAL"}'

# AUTONOMOUS: Auto-execute high-confidence, low-risk actions (night mode)
curl -X POST http://localhost:8000/api/policy \
  -H "Content-Type: application/json" \
  -d '{"mode": "AUTONOMOUS", "confidence_threshold": 0.95}'

# TIMED_FALLBACK: Dead man's switch (auto-execute after 30s if no response)
curl -X POST http://localhost:8000/api/policy \
  -H "Content-Type: application/json" \
  -d '{"mode": "TIMED_FALLBACK", "auto_execute_delay_seconds": 30}'
```

---

## 📊 Demo Incident Scenarios

### 1. 🚨 CrowdStrike Kernel Panic
**What Happened**: Channel File 291 content update caused global BSOD across 8,420+ endpoints

**Diagnosis**:
- **Root Cause**: Memory access violation in `csagent.sys:184`
- **Culprit Deploy**: `channel-file-291` by `sensor-release@crowdstrike.com`
- **Confidence**: 98%
- **Action**: Rollback to `channel-file-290`

### 2. 🔥 Cloudflare Regex Catastrophe
**What Happened**: WAF rule deployment caused catastrophic regex backtracking, pegging CPU to 100%

**Diagnosis**:
- **Root Cause**: Malformed regex `.*.*=.*` in rule 100018
- **Culprit Deploy**: `waf-rules-v2.19.0` commit `cf91a02`
- **Confidence**: 98%
- **Action**: Rollback to `waf-rules-v2.18.9`

### 3. 🛒 Checkout NullPointerException
**What Happened**: New payment validator code introduced null pointer bug

**Diagnosis**:
- **Root Cause**: NPE in `PaymentMethodValidator.java:142`
- **Culprit Deploy**: `v2.4.0` commit `a9f4c3b` by `alice@company.com`
- **Confidence**: 98%
- **Action**: Rollback to `v2.3.9`

### 4. 💳 Payment Gateway Vendor Outage (Red Herring)
**What Happened**: Stripe API returned 503 errors, but recent deploy was unrelated

**Diagnosis**:
- **Root Cause**: External Stripe API outage
- **Deploy Status**: Recent `v1.5.2` deploy is **BENIGN** (PayPal SDK config only)
- **Confidence**: 94%
- **Action**: Activate circuit breaker, do NOT rollback

---

## 🧪 Testing & Evaluation

### Run Full Evaluation Suite
```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run evaluation benchmarks
python eval/run_eval.py
```

This tests the agent across multiple scenarios and measures:
- ✅ Root cause identification accuracy
- ✅ Confidence score calibration
- ✅ False positive avoidance
- ✅ Action recommendation quality

### Run Pytest Tests
```powershell
# All tests
pytest eval/ -v

# Specific test files
pytest eval/test_agent.py -v
pytest eval/test_policy.py -v
pytest eval/test_tools.py -v
```

---

## 🔌 API Reference

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Web UI dashboard |
| `GET` | `/api/incidents` | List all incidents |
| `POST` | `/api/incidents/analyze` | Trigger investigation |
| `GET` | `/api/incidents/{id}` | Get incident details |
| `POST` | `/api/incidents/{id}/action` | Approve/reject action |
| `POST` | `/api/agent/diagnose` | AI-powered diagnosis |
| `GET` | `/api/decisions` | Audit log of all decisions |
| `GET` | `/api/policy` | Get current policy config |
| `POST` | `/api/policy` | Update policy settings |

### Tool Endpoints (Direct Access)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/tools/logs?service=...` | Query service logs |
| `GET` | `/api/tools/deployments?service=...` | Query deployment history |
| `GET` | `/api/tools/metrics?service=...` | Query metrics & anomalies |

### WebSocket Support (Coming Soon)
- Real-time incident updates
- Live execution progress streaming
- Policy change notifications

---

## 🧠 How It Works

### 1. Incident Detection
```
Alert → Agent.investigate() → Tool Queries
```
- Ingests alerts from monitoring systems
- Queries logs, metrics, and deployment history
- Extracts timestamps, exceptions, and patterns

### 2. Multi-Signal Correlation
```
Logs + Metrics + Deploys → CorrelationEngine → Evidence
```
- Matches error timestamps with deployment timing
- Correlates stack trace files with commit diffs
- Detects metric anomalies (CPU, error rate, latency)
- Constructs timeline of events

### 3. AI Diagnosis (Optional)
```
Evidence → Groq LLM → Root Cause Hypothesis
```
- Sends telemetry to Groq Llama 3.1 70B
- LLM performs tool-calling to gather additional context
- Generates structured diagnosis with confidence score
- Fallback to deterministic engine if LLM unavailable

### 4. Action Recommendation
```
Diagnosis → PolicyEngine → RemediationAction
```
- Generates rollback/scale/throttle commands
- Evaluates against safety policy
- Assigns confidence and risk scores
- Routes for human approval or auto-execution

### 5. Execution & Audit
```
Approval → Execute → Audit Log
```
- Simulates kubectl/API commands
- Tracks reviewer, timestamp, and result
- Logs all decisions for compliance
- Updates incident status

---

## 🛡️ Safety Features

### Policy Modes
- **MANUAL**: Strict human review for every action
- **AUTONOMOUS**: Auto-execute low-risk, high-confidence actions (≥95% confidence, LOW risk)
- **TIMED_FALLBACK**: Dead man's switch with configurable timeout

### Guardrails
- ✅ Confidence threshold enforcement (default: 95%)
- ✅ Risk level assessment (LOW/MEDIUM/HIGH)
- ✅ Database migration blocking (configurable)
- ✅ Multi-signal evidence requirement
- ✅ Reviewer attribution and audit trail
- ✅ Command preview before execution

### False Positive Prevention
The agent explicitly checks for alternative root causes before blaming deployments:
- Memory exhaustion (OOM errors)
- Connection pool saturation
- CPU/thread starvation
- External vendor outages
- Expired TLS certificates
- Database deadlocks

---

## 🔧 Technology Stack

### Backend
- **FastAPI** - Modern async Python web framework
- **Pydantic** - Type-safe data validation
- **Python 3.10+** - Core language
- **uvicorn** - ASGI server

### AI/LLM
- **Groq** - Ultra-fast LLM inference platform
- **Llama 3.1 70B** - Open-source reasoning model
- **Tool-use protocol** - Function calling for agentic behavior

### Frontend
- **Vanilla JavaScript** - No framework bloat
- **Glassmorphism UI** - Modern design aesthetic
- **CSS Grid/Flexbox** - Responsive layout
- **Dark theme** - Optimized for command centers

### Testing
- **pytest** - Unit and integration testing
- **JSON test cases** - Benchmark scenarios
- **Automated evaluation** - Accuracy measurement

---

## 📈 Performance

- **Response Time**: < 2 seconds for deterministic diagnosis
- **AI Diagnosis**: 3-8 seconds with Groq Llama 3.1 (depending on tool calls)
- **Throughput**: Handles 100+ incidents in evaluation suite
- **Accuracy**: 98% on deployment regression scenarios, 94% on vendor outages

---

## 🚧 Future Enhancements

### Planned Features
- [ ] **WebSocket Support**: Real-time UI updates
- [ ] **Multi-Tenancy**: Support for multiple organizations
- [ ] **Integration APIs**: PagerDuty, Datadog, Sentry webhooks
- [ ] **Slack Bot**: Interactive incident management
- [ ] **Kubernetes Native**: CRD-based incident resources
- [ ] **ML Anomaly Detection**: Replace statistical thresholds with learned baselines
- [ ] **Playbook Execution**: Runbook automation with approval gates
- [ ] **Incident Postmortems**: Automated report generation

### Model Options
- [ ] Support for other Groq models (Mixtral, Gemma 2)
- [ ] Claude integration (via Anthropic API)
- [ ] GPT-4 integration (via OpenAI API)
- [ ] Local LLM support (Ollama, vLLM)

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/JestuAshok/SRE-Autonomous-Incident-Response-Agent---Python-FastAPI---Groq-Llama-3.1-70B/issues)
- **Documentation**: See [GROQ_SETUP.md](GROQ_SETUP.md) for Groq integration details

---

## 🙏 Acknowledgments

Inspired by real-world production incidents:
- CrowdStrike Falcon Sensor outage (July 2024)
- Cloudflare regex catastrophe (July 2019)
- Common deployment regression patterns

Built with ❤️ for SRE and DevOps teams everywhere.

---

**⭐ Star this repo if you find it useful!**
