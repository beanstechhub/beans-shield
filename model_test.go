package shield

import (
	"context"
	"testing"
	"time"
)

type fixedScorer struct {
	value float64
}

func (f *fixedScorer) Score(_ []float64) float64 {
	return f.value
}

func TestHybridScoring_LowMLScore_NoImpact(t *testing.T) {
	s := New(WithScorer(&fixedScorer{value: 0.1}, 0.5))
	tx := &Transaction{
		ID:        "tx_ml_1",
		UserID:    "usr_ml",
		Type:      "pix_out",
		Amount:    50000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow with low ML score, got %s (score: %.2f)", result.Decision, result.Score)
	}
}

func TestHybridScoring_HighMLScore_TriggersReview(t *testing.T) {
	s := New(WithScorer(&fixedScorer{value: 0.9}, 0.8))
	tx := &Transaction{
		ID:        "tx_ml_2",
		UserID:    "usr_ml_high",
		Type:      "pix_out",
		Amount:    50000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	if result.Decision == DecisionAllow {
		t.Errorf("expected review/block with high ML score (0.9 * 0.8 weight), got allow (score: %.2f)", result.Score)
	}
}

func TestHybridScoring_FullMLWeight(t *testing.T) {
	s := New(WithScorer(&fixedScorer{value: 1.0}, 1.0))
	tx := &Transaction{
		ID:        "tx_ml_3",
		UserID:    "usr_ml_full",
		Type:      "pix_out",
		Amount:    10000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	// With weight=1.0, rule score is ignored. ML score 1.0 * 10 * 1.0 = 10.0 >= 8.0 = block
	if result.Decision != DecisionBlock {
		t.Errorf("expected block with full ML weight and score 1.0, got %s (score: %.2f)", result.Decision, result.Score)
	}
}

func TestHybridScoring_ZeroWeight_RulesOnly(t *testing.T) {
	s := New(WithScorer(&fixedScorer{value: 1.0}, 0.0))
	tx := &Transaction{
		ID:        "tx_ml_4",
		UserID:    "usr_ml_zero",
		Type:      "pix_out",
		Amount:    50000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	if result.Decision != DecisionAllow {
		t.Errorf("expected allow with zero ML weight (rules-only), got %s (score: %.2f)", result.Decision, result.Score)
	}
}

func TestHybridScoring_BlendFormula(t *testing.T) {
	ruleScore := 3.0
	mlScore := 0.7
	weight := 0.4

	expected := ruleScore*(1-weight) + mlScore*10*weight
	got := blendScores(ruleScore, mlScore, weight)

	if got != expected {
		t.Errorf("blendScores(%.1f, %.1f, %.1f) = %.2f, want %.2f", ruleScore, mlScore, weight, got, expected)
	}
}

func TestThresholdScorer_HighAmount(t *testing.T) {
	scorer := &ThresholdScorer{Threshold: 0.5}
	features := ExtractFeatures(&Transaction{
		ID:        "tx_feat_1",
		UserID:    "usr_feat",
		Type:      "pix_out",
		Amount:    8_000_000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}, NewVelocityCounter())

	score := scorer.Score(features)
	if score <= 0.0 {
		t.Errorf("expected positive score for high amount, got %.4f", score)
	}
	if score > 1.0 {
		t.Errorf("score should be capped at 1.0, got %.4f", score)
	}
}

func TestThresholdScorer_LowAmount(t *testing.T) {
	scorer := &ThresholdScorer{Threshold: 0.5}
	features := ExtractFeatures(&Transaction{
		ID:        "tx_feat_2",
		UserID:    "usr_feat_low",
		Type:      "pix_in",
		Amount:    10000,
		Currency:  "BRL",
		CreatedAt: time.Date(2025, 6, 15, 14, 0, 0, 0, time.UTC),
	}, NewVelocityCounter())

	score := scorer.Score(features)
	if score >= 0.3 {
		t.Errorf("expected low score for small safe transaction, got %.4f", score)
	}
}

func TestFeatureExtraction_Length(t *testing.T) {
	vc := NewVelocityCounter()
	tx := &Transaction{
		ID:          "tx_feat_len",
		UserID:      "usr_feat_len",
		Type:        "swap",
		Amount:      500000,
		Currency:    "BRL",
		Destination: "dest_123",
		CreatedAt:   time.Now(),
	}

	features := ExtractFeatures(tx, vc)
	expectedLen := 14
	if len(features) != expectedLen {
		t.Errorf("expected %d features, got %d", expectedLen, len(features))
	}
}

func TestFeatureExtraction_TransactionTypeOneHot(t *testing.T) {
	vc := NewVelocityCounter()
	tx := &Transaction{
		ID:        "tx_onehot",
		UserID:    "usr_onehot",
		Type:      "withdrawal",
		Amount:    100000,
		Currency:  "BRL",
		CreatedAt: time.Now(),
	}

	features := ExtractFeatures(tx, vc)
	// One-hot starts at index 3: pix_out(3), pix_in(4), withdrawal(5), swap(6), crypto_buy(7)
	if features[3] != 0.0 {
		t.Errorf("pix_out should be 0, got %.1f", features[3])
	}
	if features[4] != 0.0 {
		t.Errorf("pix_in should be 0, got %.1f", features[4])
	}
	if features[5] != 1.0 {
		t.Errorf("withdrawal should be 1, got %.1f", features[5])
	}
	if features[6] != 0.0 {
		t.Errorf("swap should be 0, got %.1f", features[6])
	}
	if features[7] != 0.0 {
		t.Errorf("crypto_buy should be 0, got %.1f", features[7])
	}
}

func TestHybridScoring_WithThresholdScorer(t *testing.T) {
	scorer := &ThresholdScorer{Threshold: 0.3}
	s := New(WithScorer(scorer, 0.5))

	tx := &Transaction{
		ID:          "tx_hybrid_threshold",
		UserID:      "usr_hybrid",
		Type:        "pix_out",
		Amount:      6_000_000,
		Currency:    "BRL",
		Destination: "new_dest_999",
		CreatedAt:   time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	if result.Score <= 0 {
		t.Errorf("expected positive blended score, got %.2f", result.Score)
	}
}
