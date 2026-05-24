package shield

import (
	"fmt"
	"time"
)

func bettingRules() []MerchantRule {
	return []MerchantRule{
		bettingRoundTripRule(),
		bettingSmurfingRule(),
		bettingStructuringRule(),
		bettingSyndicateRule(),
		merchantVelocityRule(),
		bettingTicketDeviationRule(),
	}
}

// Detects deposit followed by withdrawal within 24h with no betting activity (money laundering pattern).
func bettingRoundTripRule() MerchantRule {
	return MerchantRule{
		Name:   "betting_round_trip",
		Risk:   RiskCritical,
		Action: DecisionBlock,
		Condition: func(ctx *EvalContext) bool {
			tx := ctx.Tx
			if tx.Type != "withdrawal" && tx.Type != "pix_out" {
				return false
			}

			merchantID := ctx.MerchantConfig.MerchantID
			userID := tx.UserID

			depositKey := fmt.Sprintf("merchant:%s:user:%s:pix_in", merchantID, userID)
			_, depositSum := ctx.Velocity.Count(depositKey, 24*time.Hour)

			if depositSum > 100_000 && tx.Amount > int64(float64(depositSum)*0.80) {
				return true
			}
			return false
		},
	}
}

// Detects multiple accounts on same merchant from same IP within 1 hour.
func bettingSmurfingRule() MerchantRule {
	return MerchantRule{
		Name:   "betting_smurfing",
		Risk:   RiskHigh,
		Action: DecisionReview,
		Condition: func(ctx *EvalContext) bool {
			tx := ctx.Tx
			if tx.IP == "" {
				return false
			}

			merchantID := ctx.MerchantConfig.MerchantID
			ipKey := fmt.Sprintf("ip:%s:merchant:%s", tx.IP, merchantID)
			count, _ := ctx.Velocity.Count(ipKey, 1*time.Hour)

			if count > 3 {
				return true
			}
			return false
		},
	}
}

// Detects transactions structured to avoid reporting thresholds (e.g. COAF R$50k).
func bettingStructuringRule() MerchantRule {
	return MerchantRule{
		Name:   "betting_structuring",
		Risk:   RiskHigh,
		Action: DecisionReview,
		Condition: func(ctx *EvalContext) bool {
			tx := ctx.Tx
			merchantID := ctx.MerchantConfig.MerchantID
			userID := tx.UserID

			if tx.Amount >= 5_000_000 {
				return false
			}

			key := fmt.Sprintf("merchant:%s:user:%s:tx", merchantID, userID)
			count, sum := ctx.Velocity.Count(key, 24*time.Hour)

			totalSum := sum + tx.Amount
			totalCount := count + 1

			if totalSum > 4_500_000 && totalCount >= 3 {
				return true
			}
			return false
		},
	}
}

// Detects coordinated withdrawals from multiple accounts within 10 minutes.
func bettingSyndicateRule() MerchantRule {
	return MerchantRule{
		Name:   "betting_syndicate",
		Risk:   RiskCritical,
		Action: DecisionBlock,
		Condition: func(ctx *EvalContext) bool {
			tx := ctx.Tx
			if tx.Type != "withdrawal" && tx.Type != "pix_out" {
				return false
			}

			merchantID := ctx.MerchantConfig.MerchantID
			withdrawalKey := fmt.Sprintf("merchant:%s:withdrawal", merchantID)
			count, _ := ctx.Velocity.Count(withdrawalKey, 10*time.Minute)

			if count > 5 {
				return true
			}
			return false
		},
	}
}

// Enforces merchant-specific velocity limits (flags at 150% of configured max).
func merchantVelocityRule() MerchantRule {
	return MerchantRule{
		Name:   "merchant_velocity",
		Risk:   RiskHigh,
		Action: DecisionReview,
		Condition: func(ctx *EvalContext) bool {
			merchantID := ctx.MerchantConfig.MerchantID
			maxPerHour := ctx.MerchantConfig.MaxTransactionsPerHour

			if maxPerHour <= 0 {
				return false
			}

			key := fmt.Sprintf("merchant:%s:tx", merchantID)
			count, _ := ctx.Velocity.Count(key, 1*time.Hour)

			threshold := int(float64(maxPerHour) * 1.5)
			if count > threshold {
				return true
			}
			return false
		},
	}
}

// Detects sudden spikes in average transaction size (24h avg vs 30d avg, ratio > 3.0).
func bettingTicketDeviationRule() MerchantRule {
	return MerchantRule{
		Name:   "betting_ticket_deviation",
		Risk:   RiskMedium,
		Action: DecisionReview,
		Condition: func(ctx *EvalContext) bool {
			tx := ctx.Tx
			merchantID := ctx.MerchantConfig.MerchantID
			userID := tx.UserID

			key := fmt.Sprintf("merchant:%s:user:%s:tx", merchantID, userID)

			count30d, sum30d := ctx.Velocity.Count(key, 30*24*time.Hour)
			if count30d < 5 {
				return false
			}
			avg30d := float64(sum30d) / float64(count30d)

			count24h, sum24h := ctx.Velocity.Count(key, 24*time.Hour)
			if count24h == 0 {
				count24h = 1
				sum24h = tx.Amount
			}
			avg24h := (float64(sum24h) + float64(tx.Amount)) / float64(count24h+1)

			if avg30d == 0 {
				return false
			}

			ratio := avg24h / avg30d
			return ratio > 3.0
		},
	}
}
