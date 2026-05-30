# beans-shield

**Security toolkit for financial infrastructure:** real-time fraud detection + vulnerability scanner for Go codebases.

[![Go Reference](https://pkg.go.dev/badge/github.com/beanstech/beans-shield.svg)](https://pkg.go.dev/github.com/beanstech/beans-shield)
[![Go Report Card](https://goreportcard.com/badge/github.com/beanstech/beans-shield)](https://goreportcard.com/report/github.com/beanstech/beans-shield)

---

## Two Engines, One Mission

beans-shield protects financial software at two levels:

### 1. Runtime Fraud Detection
Real-time transaction scoring for Pix, crypto, and betting — sub-50μs decisions with rules + ML hybrid scoring.

### 2. Code Vulnerability Scanner
Static analysis + AI-powered deep scanning for Go codebases. Finds SQL injection, hardcoded secrets, weak crypto, race conditions, auth bypasses, and more.

```bash
# Scan any Go project for vulnerabilities
go run github.com/beanstech/beans-shield/examples/scan@latest ./my-fintech-api
```

```
beans-shield scanner: 2 findings in 106 files
  Critical: 1 | High: 1 | Medium: 0 | Low: 0

[1] Potential SQL injection via string concatenation (critical)
    File: internal/repository/vehicle.go:144
    CWE: CWE-89
    Fix: Use parameterized queries with $1, $2 placeholders.

[2] Hardcoded secret in source code (high)
    File: internal/config/config.go:58
    CWE: CWE-798
    Fix: Load secrets from environment variables or a secret manager.
```

---

## Why beans-shield?

Most security tools are either:
- **Expensive SaaS** (Snyk, Checkmarx, Featurespace) — $50k+/year
- **Generic** — not tuned for financial infrastructure patterns
- **Closed source** — can't audit, can't extend, can't trust

beans-shield is open-source, Go-native, zero-dependency, and built specifically for financial software.

### For fintech developers:
- Sub-millisecond fraud decisions without vendor lock-in
- Explainable rules for BACEN/COAF compliance
- Sector-specific intelligence (betting, crypto, e-commerce)

### For security teams:
- AST-based static analysis with CWE mappings
- AI-powered deep scanning via Claude API (optional)
- CI/CD integration — exit code 2 on critical/high findings

---

## Quick Start

```bash
go get github.com/beanstech/beans-shield
```

```go
package main

import (
    "context"
    "fmt"
    "time"

    shield "github.com/beanstech/beans-shield"
)

func main() {
    s := shield.New()

    result := s.Evaluate(context.Background(), &shield.Transaction{
        ID:          "tx_001",
        UserID:      "user_abc",
        Type:        "pix_out",
        Amount:      150_000, // R$1,500.00 in centavos
        Currency:    "BRL",
        Destination: "99988877766",
        IP:          "189.40.72.15",
        CreatedAt:   time.Now(),
    })

    fmt.Printf("%s (score: %.1f)\n", result.Decision, result.Score)
    // Output: allow (score: 0.0)
}
```

---

## How It Works

```
Transaction → [Global Rules] → [Sector Rules] → [Custom Rules] → Decision
                    ↕                  ↕                ↕
              VelocityCounter (sliding window, in-memory)
```

Every transaction passes through three layers of rules. Each rule that fires contributes a risk score. The final decision is:

| Condition | Decision |
|-----------|----------|
| Score < 4.0 and max risk ≤ Medium | `allow` |
| Score ≥ 4.0 or max risk = High | `review` |
| Score ≥ 8.0 or max risk = Critical | `block` |

---

## Built-in Rules

### Global Rules (apply to all transactions)

| Rule | What it detects | Default thresholds |
|------|----------------|-------------------|
| `high_single_amount` | Single large transaction | Medium: >R$10k, High: >R$50k |
| `velocity_count_1h` | Too many transactions per hour | Medium: >5, High: >10, Critical: >20 |
| `velocity_amount_24h` | Daily volume spike | High: >R$100k, Critical: >R$200k |
| `unusual_hour` | High-value tx between 00:00–06:00 | Medium: >R$5k at night |
| `new_destination_high_amount` | First transfer to unknown recipient | Medium: >R$2k, High: >R$10k |
| `rapid_fire` | Burst of transactions in 2 minutes | High: >3, Critical: >5 |

### Betting Sector Rules

| Rule | What it detects |
|------|----------------|
| `betting_round_trip` | Deposit → withdrawal within 24h (no betting = money laundering) |
| `betting_smurfing` | Multiple accounts from same IP on same merchant |
| `betting_structuring` | Transactions structured below COAF R$50k threshold |
| `betting_syndicate` | Coordinated withdrawals from multiple accounts in 10min |
| `merchant_velocity` | Merchant exceeding 150% of configured hourly limit |
| `betting_ticket_deviation` | Sudden spike in average transaction size (3x historical) |

---

## Merchant-Specific Evaluation

For payment gateways and PSPs that serve multiple merchants:

```go
config := shield.DefaultBettingConfig("merchant_123")

// Or fully custom:
config := &shield.MerchantConfig{
    MerchantID:             "merchant_456",
    Sector:                 "crypto",
    MaxDailyVolume:         1_000_000,
    MaxSingleTransaction:   200_000,
    MaxTransactionsPerHour: 2000,
    CooloffHours:           24,
    CustomRules: []shield.MerchantRule{
        {
            Name:   "block_sanctioned_wallet",
            Risk:   shield.RiskCritical,
            Action: shield.DecisionBlock,
            Condition: func(ctx *shield.EvalContext) bool {
                return isSanctioned(ctx.Tx.Destination)
            },
        },
    },
}

result, _ := s.EvaluateWithMerchant(ctx, tx, config)
```

---

## Custom Rules

Add your own rules alongside the defaults:

```go
myRule := shield.Rule{
    Name: "block_vpn_high_value",
    Evaluate: func(tx *shield.Transaction, vc *shield.VelocityCounter) (bool, shield.RiskLevel) {
        if isVPN(tx.IP) && tx.Amount > 500_000 {
            return true, shield.RiskHigh
        }
        return false, shield.RiskLow
    },
}

s := shield.New(shield.WithRules(append(shield.DefaultRules(), myRule)))
```

---

## Persistence

Implement the `Persister` interface to store decisions in your database:

```go
type MyPersister struct {
    db *sql.DB
}

func (p *MyPersister) PersistDecision(ctx context.Context, txID, userID string, amount int64, decision shield.Decision, risk shield.RiskLevel, score float64, rules []string) error {
    _, err := p.db.ExecContext(ctx,
        "INSERT INTO fraud_decisions (tx_id, user_id, amount, decision, risk, score, rules) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        txID, userID, amount, decision, risk, score, rules,
    )
    return err
}

s := shield.New(shield.WithPersister(&MyPersister{db: db}))
```

---

## Performance

beans-shield is designed for hot-path evaluation:

- **< 50μs** per evaluation (benchmarked on commodity hardware)
- **Zero allocations** on the happy path (allow with no rules triggered)
- **Lock-free reads** — uses `sync.RWMutex` for velocity counters
- **Automatic cleanup** — expired windows are garbage-collected every 5 minutes

---

## Regulatory Compliance

beans-shield was built to satisfy:

| Regulation | How beans-shield helps |
|-----------|----------------------|
| **BACEN Resolução 403/2024** | Real-time Pix fraud detection with explainable decisions |
| **COAF** (AML reporting) | Structuring detection below R$50k threshold |
| **LGPD Art. 46** | Audit trail via Persister interface |
| **PCI-DSS v4.0** | Transaction monitoring requirement (Req. 10) |
| **HKMA TM-G-1** | Technology risk management for authorized institutions |

---

## Vulnerability Scanner

### Static Analysis (8 built-in rules)

| ID | Rule | Severity | CWE |
|----|------|----------|-----|
| BSEC-001 | SQL Injection (string concat) | Critical | CWE-89 |
| BSEC-002 | Hardcoded Secrets | High | CWE-798 |
| BSEC-003 | Weak Cryptography (MD5, SHA1, DES, RC4) | High | CWE-327 |
| BSEC-004 | Command Injection (exec.Command) | Critical | CWE-78 |
| BSEC-005 | Race Conditions (goroutine + pkg var) | Medium | CWE-362 |
| BSEC-006 | Unvalidated Redirects | Medium | CWE-601 |
| BSEC-007 | Insecure TLS (skip verify, old versions) | High | CWE-295/326 |
| BSEC-008 | Error Information Leak | Low | CWE-209 |

### AI-Powered Deep Scan (optional)

For complex vulnerabilities that static analysis can't catch (logic flaws, auth bypasses, TOCTOU):

```go
import "github.com/beanstech/beans-shield/scanner"

s := scanner.New()
ai := scanner.NewAIScannerFromEnv() // uses ANTHROPIC_API_KEY

staticResult, aiFindings, _ := ai.DeepScan(ctx, s, "./my-project")
```

The AI scanner uses Claude to reason about code semantics — finding multi-step vulnerabilities that survive years of manual review and millions of automated tests.

### CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    go run github.com/beanstech/beans-shield/examples/scan@latest .
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}  # optional, for deep scan
```

Exit codes: `0` = clean, `2` = critical/high findings.

---

## Architecture

```
beans-shield/
├── shield.go          # Core fraud engine
├── rules.go           # Configurable fraud rules
├── features.go        # ML feature extraction (14 features)
├── model.go           # Scorer interface + hybrid blending
├── merchant.go        # Multi-merchant evaluation
├── betting.go         # Betting-sector fraud rules
├── scanner/
│   ├── scanner.go     # Vulnerability scanner engine
│   ├── rules.go       # 8 static analysis rules (AST-based)
│   └── ai.go          # Claude-powered deep analysis
├── models/            # Trained ML model (ONNX + LightGBM)
├── scripts/train.py   # Model training pipeline
└── examples/
    ├── basic/         # Fraud detection example
    └── scan/          # Vulnerability scanner CLI
```

---

## Roadmap

- [x] ~~ML score integration (hybrid rules + model)~~
- [x] ~~Vulnerability scanner with CWE mappings~~
- [x] ~~AI-powered deep scanning via Claude~~
- [ ] Redis-backed VelocityCounter (distributed deployments)
- [ ] E-commerce and Crypto/DeFi sector rules
- [ ] SARIF output format for GitHub Security tab
- [ ] Multi-language support (TypeScript, Python, Rust)
- [ ] OpenTelemetry metrics export
- [ ] CVE database correlation

---

## Contributing

PRs welcome. Please include tests for new rules.

## License

MIT — use it, fork it, ship it.

---

Built by [BeansTech](https://beanstech.com.br) — battle-tested in production processing real Pix and crypto transactions.
