package shield

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestEvaluateWithMerchant_NilConfig(t *testing.T) {
	s := New()
	tx := &Transaction{
		ID:        "tx_nil_config",
		UserID:    "usr_1",
		Type:      "pix_out",
		Amount:    50000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	result, err := s.EvaluateWithMerchant(context.Background(), tx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

func TestBettingRoundTrip_Detected(t *testing.T) {
	s := New()
	config := DefaultBettingConfig("bet_merchant_1")

	s.RecordMerchantDeposit("bet_merchant_1", "usr_roundtrip", 500_000)

	tx := &Transaction{
		ID:        "tx_withdrawal_roundtrip",
		UserID:    "usr_roundtrip",
		Type:      "withdrawal",
		Amount:    450_000,
		Currency:  "BRL",
		IP:        "192.168.1.1",
		CreatedAt: time.Now(),
	}

	result, err := s.EvaluateWithMerchant(context.Background(), tx, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !hasRule(result.Rules, "betting_round_trip") {
		t.Errorf("expected betting_round_trip, got rules: %v", result.Rules)
	}
	if result.Decision != DecisionBlock {
		t.Errorf("expected block, got %s", result.Decision)
	}
}

func TestBettingSmurfing_Detected(t *testing.T) {
	s := New()
	config := DefaultBettingConfig("bet_smurf")

	for i := 0; i < 4; i++ {
		s.velocity.Record(fmt.Sprintf("ip:%s:merchant:%s", "10.0.0.99", "bet_smurf"), 100_000)
	}

	tx := &Transaction{
		ID:        "tx_smurf_5",
		UserID:    "usr_smurf_5",
		Type:      "pix_in",
		Amount:    100_000,
		Currency:  "BRL",
		IP:        "10.0.0.99",
		CreatedAt: time.Now(),
	}

	result, err := s.EvaluateWithMerchant(context.Background(), tx, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(result.Rules, "betting_smurfing") {
		t.Errorf("expected betting_smurfing, got rules: %v", result.Rules)
	}
}

func TestBettingStructuring_Detected(t *testing.T) {
	s := New()
	config := DefaultBettingConfig("bet_struct")

	for i := 0; i < 2; i++ {
		s.velocity.Record(fmt.Sprintf("merchant:%s:user:%s:tx", "bet_struct", "usr_struct"), 2_000_000)
	}

	tx := &Transaction{
		ID:        "tx_struct_3",
		UserID:    "usr_struct",
		Type:      "pix_in",
		Amount:    1_000_000,
		Currency:  "BRL",
		IP:        "10.0.0.50",
		CreatedAt: time.Now(),
	}

	result, err := s.EvaluateWithMerchant(context.Background(), tx, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(result.Rules, "betting_structuring") {
		t.Errorf("expected betting_structuring, got rules: %v", result.Rules)
	}
}

func TestBettingSyndicate_Detected(t *testing.T) {
	s := New()
	config := DefaultBettingConfig("bet_synd")

	for i := 0; i < 6; i++ {
		s.RecordMerchantWithdrawal("bet_synd", 200_000)
	}

	tx := &Transaction{
		ID:        "tx_synd_7",
		UserID:    "usr_synd_7",
		Type:      "withdrawal",
		Amount:    200_000,
		Currency:  "BRL",
		IP:        "10.0.1.1",
		CreatedAt: time.Now(),
	}

	result, err := s.EvaluateWithMerchant(context.Background(), tx, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(result.Rules, "betting_syndicate") {
		t.Errorf("expected betting_syndicate, got rules: %v", result.Rules)
	}
	if result.Decision != DecisionBlock {
		t.Errorf("expected block, got %s", result.Decision)
	}
}

func TestMerchantVelocity_Detected(t *testing.T) {
	s := New()
	config := &MerchantConfig{
		MerchantID:             "bet_vel",
		Sector:                 "betting",
		MaxTransactionsPerHour: 10,
	}

	for i := 0; i < 16; i++ {
		s.velocity.Record(fmt.Sprintf("merchant:%s:tx", "bet_vel"), 10_000)
	}

	tx := &Transaction{
		ID:        "tx_vel_over",
		UserID:    "usr_vel",
		Type:      "pix_in",
		Amount:    10_000,
		Currency:  "BRL",
		IP:        "10.0.2.1",
		CreatedAt: time.Now(),
	}

	result, err := s.EvaluateWithMerchant(context.Background(), tx, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(result.Rules, "merchant_velocity") {
		t.Errorf("expected merchant_velocity, got rules: %v", result.Rules)
	}
}

func TestCustomMerchantRules(t *testing.T) {
	s := New()
	config := &MerchantConfig{
		MerchantID: "custom_merchant",
		Sector:     "ecommerce",
		CustomRules: []MerchantRule{
			{
				Name:   "custom_block_large",
				Risk:   RiskCritical,
				Action: DecisionBlock,
				Condition: func(ctx *EvalContext) bool {
					return ctx.Tx.Amount > 2_500_000
				},
			},
		},
	}

	tx := &Transaction{
		ID:        "tx_custom_large",
		UserID:    "usr_custom",
		Type:      "pix_out",
		Amount:    3_000_000,
		Currency:  "BRL",
		IP:        "10.0.5.1",
		CreatedAt: time.Now(),
	}

	result, err := s.EvaluateWithMerchant(context.Background(), tx, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasRule(result.Rules, "custom_block_large") {
		t.Errorf("expected custom_block_large, got rules: %v", result.Rules)
	}
	if result.Decision != DecisionBlock {
		t.Errorf("expected block, got %s", result.Decision)
	}
}

func hasRule(rules []string, name string) bool {
	for _, r := range rules {
		if r == name {
			return true
		}
	}
	return false
}
