# Agentic AI Log Analyzer

An intelligent, self-learning log analysis system that pulls logs from **Splunk**, performs **root-cause analysis** using the **MiniMax LLM**, learns from past cases via user feedback, and fires **email + webhook alerts** on errors or suspicious activity.

---

## Architecture

```
Splunk REST API
      │
      ▼
SplunkIngestor          ← pulls JSON log events every N seconds
      │
      ▼
KnowledgeBase           ← finds similar past cases (TF-IDF cosine similarity)
      │
      ▼
LLMInterface (MiniMax)  ← generates root-cause analysis + solution
      │
      ├──► KnowledgeBase  ← persists new case (SQLite)
      │
      └──► AlertManager   ← fires email / webhook if severity threshold met
                │
                └──► KnowledgeBase  ← logs alert dispatch result
```

### Three core capabilities

| # | Capability | How it works |
|---|-----------|-------------|
| 1 | **Root-cause analysis & solution** | Each log event is sent to MiniMax with a structured prompt. The LLM returns severity, summary, root cause, step-by-step solution, related components, and a confidence score. |
| 2 | **Learning from past cases** | The SQLite knowledge base stores every analysed case. When a new event arrives, TF-IDF similarity finds the most relevant **verified** past cases (those with user feedback) and injects them as few-shot examples into the LLM prompt. |
| 3 | **Alerting on errors / suspicious activity** | Any event whose log level or LLM-assessed severity matches a configured trigger level (e.g. ERROR, CRITICAL), or whose message contains suspicious keywords (brute force, SQL injection, etc.), fires alerts via email and/or webhook. |

---

## Quick Start

### 1. Install dependencies

```bash
cd log_analysis_agent
pip install -r requirements.txt
```

### 2. Configure

Edit **`config.yaml`** and fill in:

| Section | Key fields |
|---------|-----------|
| `splunk` | `host`, `username`, `password` (or `token`), `search_query` |
| `llm` | `api_key`, `group_id`, `model` |
| `alerts.email` | `smtp_host`, `sender`, `password`, `recipients` |
| `alerts.webhook` | `url`, `headers` |

### 3. Run the daemon

```bash
python main.py run
```

The agent will poll Splunk every `poll_interval_seconds` (default: 60 s), analyse new logs, and fire alerts automatically.

---

## CLI Commands

```bash
# Continuous polling daemon
python main.py run

# Analyse a local JSON log file (single event or list)
python main.py analyse --file sample_logs.json

# List the 20 most recent analysed cases
python main.py list

# Show full details of a specific case
python main.py show 42

# Submit feedback to improve future analysis
python main.py feedback 42 --result correct
python main.py feedback 42 --result incorrect --notes "Root cause was a network partition, not DB pool"
python main.py feedback 42 --result partial --notes "Solution was correct but missing step 3"
```

Global flags:

```bash
--config path/to/config.yaml   # use a non-default config file
--verbose / -v                 # enable DEBUG logging
```

---

## Feedback Loop (Learning)

After the agent analyses a case it stores it in **`knowledge_base.db`** (SQLite).  
Use `python main.py feedback <case_id> --result <correct|incorrect|partial>` to validate the LLM's output.

On future events, the agent automatically retrieves the top-N most **similar verified cases** and injects them as few-shot examples into the LLM prompt — so the model continuously improves with your domain knowledge.

```
New event → similarity search (TF-IDF)
                │
        ┌───────┴────────┐
   similar cases         no similar cases
  (with feedback)              │
        │                      │
  injected as            LLM analyses
  few-shot context       from scratch
        │
  LLM analyses with
  domain context
```

---

## Alert Channels

### Email
Sends a plain-text alert email via SMTP/TLS.  
Configure `alerts.email` in `config.yaml`.

### Webhook
Posts a JSON payload to any HTTP endpoint (Slack incoming webhooks, Teams, PagerDuty, custom handlers, etc.).  
Configure `alerts.webhook` in `config.yaml`.

**Webhook payload schema:**

```json
{
  "case_id": 17,
  "log_time": "2026-03-09T14:01:15Z",
  "log_level": "CRITICAL",
  "log_source": "auth-service",
  "log_host": "auth-server-02",
  "message_snippet": "Authentication failed 15 times...",
  "severity": "CRITICAL",
  "summary": "Possible brute-force attack on admin account",
  "root_cause": "...",
  "solution": "1. Block IP 192.168.50.12...",
  "related_components": ["auth-service", "WAF"],
  "confidence": 0.92
}
```

---

## Configuration Reference

```yaml
splunk:
  host: "https://splunk-host:8089"
  username: "admin"
  password: "..."
  token: ""                        # use token OR user/pass
  search_query: "search index=main | head 100"
  earliest_time: "-15m"
  latest_time: "now"
  poll_interval_seconds: 60
  verify_ssl: false

llm:
  provider: "minimax"
  api_key: "..."
  group_id: "..."
  model: "abab6.5s-chat"
  base_url: "https://api.minimax.chat/v1"
  max_tokens: 2048
  temperature: 0.2
  similar_cases_limit: 3          # how many past cases to inject

knowledge_base:
  db_path: "knowledge_base.db"
  similarity_threshold: 0.30      # min TF-IDF cosine score (0–1)

alerts:
  trigger_on_levels: [ERROR, CRITICAL, FATAL]
  suspicious_keywords:
    - "unauthorized"
    - "brute force"
    - "sql injection"
    # ... add your own

  email:
    enabled: true
    smtp_host: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    sender: "alerts@yourdomain.com"
    password: "..."
    recipients: ["oncall@yourdomain.com"]
    subject_prefix: "[LOG-ALERT]"

  webhook:
    enabled: true
    url: "https://hooks.yourservice.com/..."
    headers:
      Authorization: "Bearer ..."
    timeout_seconds: 10
    max_retries: 3
    retry_delay_seconds: 5
```

---

## File Structure

```
log_analysis_agent/
├── main.py                  # CLI entry point
├── log_analyzer_agent.py    # Orchestrator (pipeline logic)
├── splunk_ingestor.py       # Splunk REST API client
├── llm_interface.py         # MiniMax LLM wrapper
├── knowledge_base.py        # SQLite case store + TF-IDF similarity
├── alert_manager.py         # Email + webhook alerting
├── config.yaml              # Configuration
├── requirements.txt         # Python dependencies
├── sample_logs.json         # Example log events for testing
└── README.md
```

---

## MiniMax API Notes

- **Model**: `abab6.5s-chat` (recommended) or `abab5.5s-chat` for lower cost  
- **Group ID**: Required by MiniMax — find it in your MiniMax console dashboard  
- **Base URL**: `https://api.minimax.chat/v1`  
- The `openai` Python SDK is used since MiniMax exposes an OpenAI-compatible endpoint

---

## License

MIT
