# beans-shield

**Real-time transaction fraud detection engine for fintechs.** Zero external dependencies. Built for Pix, crypto, betting, and e-commerce.

[![Go Reference](https://pkg.go.dev/badge/github.com/beanstech/beans-shield.svg)](https://pkg.go.dev/github.com/beanstech/beans-shield)
[![Go Report Card](https://goreportcard.com/badge/github.com/beanstech/beans-shield)](https://goreportcard.com/report/github.com/beanstech/beans-shield)

---

## Why beans-shield?

Most fraud detection solutions are expensive SaaS black boxes. If you're a fintech in Latin America processing Pix, crypto swaps, or betting deposits, you need:

- **Sub-millisecond decisions** — can't add latency to real-time payments
- **Rules you can read and audit** — regulators (BACEN, COAF) want explainability
- **No vendor lock-in** — your fraud logic shouldn't live in someone else's cloud
- **Sector-specific intelligence** — betting fraud ≠ e-commerce fraud

beans-shield gives you all of this in ~500 lines of Go with zero dependencies.

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

## Architecture

```
beans-shield/
├── shield.go       # Core engine: Shield, VelocityCounter, Evaluate()
├── rules.go        # Built-in global rules (configurable thresholds)
├── merchant.go     # Multi-merchant evaluation + MerchantConfig
├── betting.go      # Betting-sector specific rules
├── shield_test.go  # Unit tests for core engine
├── merchant_test.go # Unit tests for merchant rules
└── examples/
    └── basic/main.go
```

---

## Roadmap

- [ ] Redis-backed VelocityCounter (for distributed deployments)
- [ ] E-commerce sector rules
- [ ] Crypto/DeFi sector rules
- [ ] ML score integration (hybrid rules + model)
- [ ] OpenTelemetry metrics export
- [ ] WASM build for edge evaluation

---

## Contributing

PRs welcome. Please include tests for new rules.

## License

MIT — use it, fork it, ship it.

---

Built by [BeansTech](https://beanstech.com.br) — battle-tested in production processing real Pix and crypto transactions.
