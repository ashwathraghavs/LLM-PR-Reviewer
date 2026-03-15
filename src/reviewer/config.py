"""
Central configuration for the LLM PR reviewer.
All thresholds, caps, and model settings live here.
Tune these to match your team's standards and budget.
"""

# ── Scoring ────────────────────────────────────────────────────────────────────
APPROVAL_THRESHOLD = 80   # score above which PRs auto-approve
BLOCK_THRESHOLD    = 65   # score below which PRs are blocked
SECURITY_WEIGHT    = 0.40
QUALITY_WEIGHT     = 0.35
TEST_WEIGHT        = 0.25

# ── Cost controls ──────────────────────────────────────────────────────────────
MAX_COST_PER_REVIEW   = 0.10    # USD hard ceiling per individual review
PER_REPO_DAILY_CAP    = 5.00    # USD per repo per day
ORG_MONTHLY_CAP       = 200.00  # USD total org ceiling per month
COST_ALERT_THRESHOLD  = 0.80    # alert at this fraction of each cap
MAX_INPUT_TOKENS      = 20_000  # hard token ceiling on what we send
MAX_OUTPUT_TOKENS     = 1_500   # cap model output — no open-ended generation

# ── Rate limiting ──────────────────────────────────────────────────────────────
RATE_BUCKET_CAPACITY  = 5   # max burst reviews per author per repo
RATE_REFILL_PER_HOUR  = 5   # tokens refilled per hour
DAILY_REVIEW_MAX      = 20  # hard daily ceiling per author per repo

# ── PR size limits ─────────────────────────────────────────────────────────────
MAX_LINES_FOR_LLM     = 500  # larger PRs go straight to human review

# ── Ensemble settings ──────────────────────────────────────────────────────────
ENSEMBLE_N            = 3  # number of independent judge calls
ENSEMBLE_AGREEMENT    = 2  # minimum runs a finding must appear in

# ── Anomaly detection ──────────────────────────────────────────────────────────
SPIKE_RATIO_THRESHOLD = 3.0   # alert if today > N × 7-day rolling average
SPIKE_MIN_ABSOLUTE    = 1.00  # ignore spikes below this USD value (avoid noise on cheap days)

# ── Model ──────────────────────────────────────────────────────────────────────
MODEL      = "claude-sonnet-4-5"

# Pricing — verify current values at console.anthropic.com/settings/billing
PRICING = {
    "claude-sonnet-4-5": {
        "input":  3.00 / 1_000_000,   # USD per input token
        "output": 15.00 / 1_000_000,  # USD per output token
    },
}

# ── Paths ──────────────────────────────────────────────────────────────────────
SPEND_DB_PATH          = "spend.db"
AUDIT_DB_PATH          = "review_audit.db"
RISK_REGISTRY_PATH     = ".github/file_risk_registry.yaml"
CONTRIBUTING_MD_PATH   = "CONTRIBUTING.md"
CODEOWNERS_PATH        = "CODEOWNERS"
INCIDENT_LOG_PATH      = ".github/incident_log.md"
