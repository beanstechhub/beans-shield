package shield

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

type EvalContext struct {
	Tx             *Transaction
	MerchantConfig *MerchantConfig
	Velocity       *VelocityCounter
}

type MerchantRule struct {
	Name      string
	Condition func(ctx *EvalContext) bool
	Risk      RiskLevel
	Action    Decision
}

type MerchantConfig struct {
	MerchantID             string
	Sector                 string // "betting", "ecommerce", "crypto", etc.
	MaxDailyVolume         float64
	MaxSingleTransaction   float64
	MaxTransactionsPerHour int
	CooloffHours           int
	CustomRules            []MerchantRule
}

func DefaultBettingConfig(merchantID string) *MerchantConfig {
	return &MerchantConfig{
		MerchantID:             merchantID,
		Sector:                 "betting",
		MaxDailyVolume:         100_000,
		MaxSingleTransaction:   50_000,
		MaxTransactionsPerHour: 500,
		CooloffHours:           48,
	}
}

func DefaultEcommerceConfig(merchantID string) *MerchantConfig {
	return &MerchantConfig{
		MerchantID:             merchantID,
		Sector:                 "ecommerce",
		MaxDailyVolume:         500_000,
		MaxSingleTransaction:   100_000,
		MaxTransactionsPerHour: 1000,
		CooloffHours:           24,
	}
}

func (s *Shield) EvaluateWithMerchant(ctx context.Context, tx *Transaction, merchantConfig *MerchantConfig) (*Result, error) {
	if merchantConfig == nil {
		result := s.Evaluate(ctx, tx)
		return &result, nil
	}

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

	sectorRules := s.sectorRules(merchantConfig.Sector)
	evalCtx := &EvalContext{
		Tx:             tx,
		MerchantConfig: merchantConfig,
		Velocity:       s.velocity,
	}

	for _, mr := range sectorRules {
		if mr.Condition(evalCtx) {
			triggered = append(triggered, mr.Name)
			if riskOrder(mr.Risk) > riskOrder(maxRisk) {
				maxRisk = mr.Risk
			}
			score += riskWeight(mr.Risk)
		}
	}

	for _, mr := range merchantConfig.CustomRules {
		if mr.Condition(evalCtx) {
			triggered = append(triggered, mr.Name)
			if riskOrder(mr.Risk) > riskOrder(maxRisk) {
				maxRisk = mr.Risk
			}
			score += riskWeight(mr.Risk)
		}
	}

	s.velocity.Record(fmt.Sprintf("user:%s:tx", tx.UserID), tx.Amount)
	s.velocity.Record(fmt.Sprintf("user:%s:%s", tx.UserID, tx.Type), tx.Amount)
	s.velocity.Record(fmt.Sprintf("merchant:%s:tx", merchantConfig.MerchantID), tx.Amount)
	s.velocity.Record(fmt.Sprintf("merchant:%s:user:%s:tx", merchantConfig.MerchantID, tx.UserID), tx.Amount)
	s.velocity.Record(fmt.Sprintf("ip:%s:merchant:%s", tx.IP, merchantConfig.MerchantID), tx.Amount)

	decision := DecisionAllow
	if maxRisk == RiskCritical || score >= 8.0 {
		decision = DecisionBlock
	} else if maxRisk == RiskHigh || score >= 4.0 {
		decision = DecisionReview
	}

	result := &Result{
		Decision:    decision,
		Risk:        maxRisk,
		Score:       score,
		Rules:       triggered,
		Latency:     time.Since(start).Microseconds(),
		EvaluatedAt: time.Now(),
	}

	if decision != DecisionAllow {
		slog.Warn("beans-shield: merchant transaction flagged",
			"tx_id", tx.ID,
			"user_id", tx.UserID,
			"merchant_id", merchantConfig.MerchantID,
			"sector", merchantConfig.Sector,
			"decision", decision,
			"risk", maxRisk,
			"score", score,
			"rules", triggered,
		)
	}

	if s.persister != nil {
		go func() {
			if err := s.persister.PersistDecision(ctx, tx.ID, tx.UserID, tx.Amount, decision, maxRisk, score, triggered); err != nil {
				slog.Error("beans-shield: persist merchant decision failed", "tx_id", tx.ID, "err", err)
			}
		}()
	}

	return result, nil
}

func (s *Shield) RecordMerchantWithdrawal(merchantID string, amount int64) {
	s.velocity.Record(fmt.Sprintf("merchant:%s:withdrawal", merchantID), amount)
}

func (s *Shield) RecordMerchantDeposit(merchantID, userID string, amount int64) {
	s.velocity.Record(fmt.Sprintf("merchant:%s:user:%s:pix_in", merchantID, userID), amount)
}

func (s *Shield) sectorRules(sector string) []MerchantRule {
	switch sector {
	case "betting":
		return bettingRules()
	default:
		return nil
	}
}
