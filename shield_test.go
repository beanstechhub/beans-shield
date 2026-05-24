package shield

import (
	"context"
	"testing"
	"time"
)

func TestShield_LowAmountAllowed(t *testing.T) {
	s := New()
	tx := &Transaction{
		ID:        "tx_test_1",
		UserID:    "usr_test",
		Type:      "pix_out",
		Amount:    50000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s (rules: %v)", result.Decision, result.Rules)
	}
}

func TestShield_HighAmountFlagged(t *testing.T) {
	s := New()
	tx := &Transaction{
		ID:        "tx_test_2",
		UserID:    "usr_test",
		Type:      "pix_out",
		Amount:    6_000_000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	if result.Decision == DecisionAllow {
		t.Errorf("expected review or block for high amount, got allow")
	}
}

func TestShield_RapidFireBlocked(t *testing.T) {
	s := New()
	userID := "usr_rapid"

	for i := 0; i < 6; i++ {
		tx := &Transaction{
			ID:        "tx_rapid_" + string(rune('0'+i)),
			UserID:    userID,
			Type:      "pix_out",
			Amount:    10000,
			Currency:  "BRL",
			CreatedAt: time.Now(),
		}
		s.Evaluate(context.Background(), tx)
	}

	tx := &Transaction{
		ID:        "tx_rapid_final",
		UserID:    userID,
		Type:      "pix_out",
		Amount:    10000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}
	result := s.Evaluate(context.Background(), tx)
	if result.Decision == DecisionAllow {
		t.Errorf("expected block/review after rapid fire, got allow (score: %.2f, rules: %v)", result.Score, result.Rules)
	}
}

func TestShield_NewDestinationHighAmount(t *testing.T) {
	s := New()
	tx := &Transaction{
		ID:          "tx_dest_1",
		UserID:      "usr_dest_test",
		Type:        "pix_out",
		Amount:      1_500_000,
		Currency:    "BRL",
		Destination: "12345678901",
		CreatedAt:   time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	if result.Decision == DecisionAllow {
		t.Errorf("expected flag for new destination + high amount, got allow")
	}
}

func TestShield_CustomRules(t *testing.T) {
	customRule := Rule{
		Name: "block_crypto_night",
		Evaluate: func(tx *Transaction, _ *VelocityCounter) (bool, RiskLevel) {
			if tx.Type == "crypto_buy" && tx.CreatedAt.Hour() >= 22 {
				return true, RiskHigh
			}
			return false, RiskLow
		},
	}

	s := New(WithRules(append(DefaultRules(), customRule)))
	tx := &Transaction{
		ID:        "tx_crypto_night",
		UserID:    "usr_crypto",
		Type:      "crypto_buy",
		Amount:    100_000,
		Currency:  "BRL",
		CreatedAt: time.Date(2025, 1, 15, 23, 30, 0, 0, time.UTC),
	}

	result := s.Evaluate(context.Background(), tx)
	found := false
	for _, r := range result.Rules {
		if r == "block_crypto_night" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected custom rule to trigger, got rules: %v", result.Rules)
	}
}
