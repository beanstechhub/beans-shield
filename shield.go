package shield

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Decision string

const (
	DecisionAllow  Decision = "allow"
	DecisionReview Decision = "review"
	DecisionBlock  Decision = "block"
)

type Transaction struct {
	ID          string
	UserID      string
	Type        string // "pix_out", "swap", "pix_in", "withdrawal", etc.
	Amount      int64  // smallest unit (e.g. centavos)
	Currency    string
	Destination string
	IP          string
	UserAgent   string
	DeviceID    string
	CreatedAt   time.Time
}

type Result struct {
	Decision    Decision  `json:"decision"`
	Risk        RiskLevel `json:"risk"`
	Score       float64   `json:"score"`
	Rules       []string  `json:"triggered_rules,omitempty"`
	Latency     int64     `json:"latency_us"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

type Persister interface {
	PersistDecision(ctx context.Context, txID, userID string, amount int64, decision Decision, risk RiskLevel, score float64, rules []string) error
}

type Rule struct {
	Name     string
	Evaluate func(tx *Transaction, vc *VelocityCounter) (bool, RiskLevel)
}

type Shield struct {
	velocity     *VelocityCounter
	rules        []Rule
	persister    Persister
	scorer       Scorer
	scorerWeight float64
}

type Option func(*Shield)

func WithPersister(p Persister) Option {
	return func(s *Shield) { s.persister = p }
}

func WithRules(rules []Rule) Option {
	return func(s *Shield) { s.rules = rules }
}

func New(opts ...Option) *Shield {
	s := &Shield{
		velocity: NewVelocityCounter(),
	}
	for _, opt := range opts {
		opt(s)
	}
	if len(s.rules) == 0 {
		s.rules = DefaultRules()
	}
	return s
}

func (s *Shield) Evaluate(ctx context.Context, tx *Transaction) Result {
	start := time.Now()
	var triggered []string
	maxRisk := RiskLow
	score := 0.0

	for _, rule := range s.rules {
		hit, risk := rule.Evaluate(tx, s.velocity)
		if hit {
			triggered = append(triggered, rule.Name)
			if riskOrder(risk) > riskOrder(maxRisk) {
				maxRisk = risk
			}
			score += riskWeight(risk)
		}
	}

	if s.scorer != nil {
		features := ExtractFeatures(tx, s.velocity)
		mlScore := s.scorer.Score(features)
		score = blendScores(score, mlScore, s.scorerWeight)
	}

	s.velocity.Record(fmt.Sprintf("user:%s:tx", tx.UserID), tx.Amount)
	s.velocity.Record(fmt.Sprintf("user:%s:%s", tx.UserID, tx.Type), tx.Amount)

	decision := DecisionAllow
	if maxRisk == RiskCritical || score >= 8.0 {
		decision = DecisionBlock
	} else if maxRisk == RiskHigh || score >= 4.0 {
		decision = DecisionReview
	}

	result := Result{
		Decision:    decision,
		Risk:        maxRisk,
		Score:       score,
		Rules:       triggered,
		Latency:     time.Since(start).Microseconds(),
		EvaluatedAt: time.Now(),
	}

	if decision != DecisionAllow {
		slog.Warn("beans-shield: transaction flagged",
			"tx_id", tx.ID,
			"user_id", tx.UserID,
			"decision", decision,
			"risk", maxRisk,
			"score", score,
			"rules", triggered,
		)
	}

	if s.persister != nil {
		go func() {
			if err := s.persister.PersistDecision(ctx, tx.ID, tx.UserID, tx.Amount, decision, maxRisk, score, triggered); err != nil {
				slog.Error("beans-shield: persist decision failed", "tx_id", tx.ID, "err", err)
			}
		}()
	}

	return result
}

func (s *Shield) Velocity() *VelocityCounter {
	return s.velocity
}

// VelocityCounter tracks event frequency and volume using sliding windows.
type VelocityCounter struct {
	mu      sync.RWMutex
	windows map[string]*slidingWindow
}

type slidingWindow struct {
	entries []time.Time
	sum     int64
}

func NewVelocityCounter() *VelocityCounter {
	vc := &VelocityCounter{
		windows: make(map[string]*slidingWindow),
	}
	go vc.cleanup()
	return vc
}

func (vc *VelocityCounter) Record(key string, amount int64) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	w, ok := vc.windows[key]
	if !ok {
		w = &slidingWindow{}
		vc.windows[key] = w
	}
	w.entries = append(w.entries, time.Now())
	w.sum += amount
}

func (vc *VelocityCounter) Count(key string, window time.Duration) (int, int64) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	w, ok := vc.windows[key]
	if !ok {
		return 0, 0
	}
	cutoff := time.Now().Add(-window)
	count := 0
	var sum int64
	for _, t := range w.entries {
		if t.After(cutoff) {
			count++
			sum += w.sum / int64(len(w.entries))
		}
	}
	return count, sum
}

func (vc *VelocityCounter) cleanup() {
	for {
		time.Sleep(5 * time.Minute)
		vc.mu.Lock()
		cutoff := time.Now().Add(-24 * time.Hour)
		for key, w := range vc.windows {
			var fresh []time.Time
			for _, t := range w.entries {
				if t.After(cutoff) {
					fresh = append(fresh, t)
				}
			}
			if len(fresh) == 0 {
				delete(vc.windows, key)
			} else {
				w.entries = fresh
			}
		}
		vc.mu.Unlock()
	}
}

func riskOrder(r RiskLevel) int {
	switch r {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	default:
		return 1
	}
}

func riskWeight(r RiskLevel) float64 {
	switch r {
	case RiskCritical:
		return 5.0
	case RiskHigh:
		return 3.0
	case RiskMedium:
		return 1.5
	default:
		return 0.5
	}
}
