package shield

import (
	"fmt"
	"math"
	"time"
)

var transactionTypes = []string{"pix_out", "pix_in", "withdrawal", "swap", "crypto_buy"}

func ExtractFeatures(tx *Transaction, vc *VelocityCounter) []float64 {
	features := make([]float64, 0, 14)

	features = append(features, normalizeAmount(tx.Amount))

	hour := float64(tx.CreatedAt.Hour())
	features = append(features, math.Sin(2*math.Pi*hour/24.0))
	features = append(features, math.Cos(2*math.Pi*hour/24.0))

	for _, txType := range transactionTypes {
		if tx.Type == txType {
			features = append(features, 1.0)
		} else {
			features = append(features, 0.0)
		}
	}

	key := fmt.Sprintf("user:%s:tx", tx.UserID)
	count1h, _ := vc.Count(key, 1*time.Hour)
	count24h, sum24h := vc.Count(key, 24*time.Hour)

	features = append(features, float64(count1h))
	features = append(features, float64(count24h))
	features = append(features, normalizeAmount(sum24h))

	isNewDest := 0.0
	if tx.Destination != "" {
		destKey := fmt.Sprintf("user:%s:dest:%s", tx.UserID, tx.Destination)
		destCount, _ := vc.Count(destKey, 30*24*time.Hour)
		if destCount == 0 {
			isNewDest = 1.0
		}
	}
	features = append(features, isNewDest)

	unusualHour := 0.0
	h := tx.CreatedAt.Hour()
	if h >= 0 && h < 6 {
		unusualHour = 1.0
	}
	features = append(features, unusualHour)

	relativeAmount := 0.0
	if count24h > 0 {
		avg24h := float64(sum24h) / float64(count24h)
		if avg24h > 0 {
			relativeAmount = float64(tx.Amount) / avg24h
		}
	}
	features = append(features, relativeAmount)

	return features
}

func normalizeAmount(amount int64) float64 {
	return float64(amount) / 10_000_000.0
}
