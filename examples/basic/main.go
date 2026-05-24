package main

import (
	"context"
	"fmt"
	"time"

	shield "github.com/beanstech/beans-shield"
)

func main() {
	s := shield.New()

	tx := &shield.Transaction{
		ID:          "tx_001",
		UserID:      "user_abc",
		Type:        "pix_out",
		Amount:      150_000, // R$1,500.00
		Currency:    "BRL",
		Destination: "99988877766",
		IP:          "189.40.72.15",
		CreatedAt:   time.Now(),
	}

	result := s.Evaluate(context.Background(), tx)
	fmt.Printf("Decision: %s | Risk: %s | Score: %.1f | Rules: %v\n",
		result.Decision, result.Risk, result.Score, result.Rules)

	// Merchant-specific evaluation
	config := shield.DefaultBettingConfig("merchant_betano")
	merchantResult, _ := s.EvaluateWithMerchant(context.Background(), tx, config)
	fmt.Printf("Merchant Decision: %s | Rules: %v\n",
		merchantResult.Decision, merchantResult.Rules)
}
