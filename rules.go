package shield

import (
	"fmt"
	"time"
)

func DefaultRules() []Rule {
	return []Rule{
		HighSingleAmount(1_000_000, 5_000_000),
		VelocityCount1h(5, 10, 20),
		VelocityAmount24h(10_000_000, 20_000_000),
		UnusualHour(0, 6, 500_000),
		NewDestinationHighAmount(200_000, 1_000_000),
		RapidFire(3, 5),
	}
}

// HighSingleAmount flags transactions above medium/high thresholds (in smallest currency unit).
func HighSingleAmount(mediumThreshold, highThreshold int64) Rule {
	return Rule{
		Name: "high_single_amount",
		Evaluate: func(tx *Transaction, _ *VelocityCounter) (bool, RiskLevel) {
			if tx.Amount > highThreshold {
				return true, RiskHigh
			}
			if tx.Amount > mediumThreshold {
				return true, RiskMedium
			}
			return false, RiskLow
		},
	}
}

// VelocityCount1h flags users exceeding transaction count thresholds in 1 hour.
func VelocityCount1h(medium, high, critical int) Rule {
	return Rule{
		Name: "velocity_count_1h",
		Evaluate: func(tx *Transaction, vc *VelocityCounter) (bool, RiskLevel) {
			key := fmt.Sprintf("user:%s:tx", tx.UserID)
			count, _ := vc.Count(key, 1*time.Hour)
			if count > critical {
				return true, RiskCritical
			}
			if count > high {
				return true, RiskHigh
			}
			if count > medium {
				return true, RiskMedium
			}
			return false, RiskLow
		},
	}
}

// VelocityAmount24h flags users exceeding daily volume thresholds.
func VelocityAmount24h(highThreshold, criticalThreshold int64) Rule {
	return Rule{
		Name: "velocity_amount_24h",
		Evaluate: func(tx *Transaction, vc *VelocityCounter) (bool, RiskLevel) {
			key := fmt.Sprintf("user:%s:tx", tx.UserID)
			_, totalAmount := vc.Count(key, 24*time.Hour)
			if totalAmount+tx.Amount > criticalThreshold {
				return true, RiskCritical
			}
			if totalAmount+tx.Amount > highThreshold {
				return true, RiskHigh
			}
			return false, RiskLow
		},
	}
}

// UnusualHour flags high-value transactions during off-hours.
func UnusualHour(startHour, endHour int, amountThreshold int64) Rule {
	return Rule{
		Name: "unusual_hour",
		Evaluate: func(tx *Transaction, _ *VelocityCounter) (bool, RiskLevel) {
			hour := tx.CreatedAt.Hour()
			if hour >= startHour && hour < endHour && tx.Amount > amountThreshold {
				return true, RiskMedium
			}
			return false, RiskLow
		},
	}
}

// NewDestinationHighAmount flags first-time transfers to new destinations above thresholds.
func NewDestinationHighAmount(mediumThreshold, highThreshold int64) Rule {
	return Rule{
		Name: "new_destination_high_amount",
		Evaluate: func(tx *Transaction, vc *VelocityCounter) (bool, RiskLevel) {
			if tx.Destination == "" {
				return false, RiskLow
			}
			key := fmt.Sprintf("user:%s:dest:%s", tx.UserID, tx.Destination)
			count, _ := vc.Count(key, 30*24*time.Hour)
			if count == 0 && tx.Amount > highThreshold {
				return true, RiskHigh
			}
			if count == 0 && tx.Amount > mediumThreshold {
				return true, RiskMedium
			}
			return false, RiskLow
		},
	}
}

// RapidFire flags bursts of transactions within a 2-minute window.
func RapidFire(highCount, criticalCount int) Rule {
	return Rule{
		Name: "rapid_fire",
		Evaluate: func(tx *Transaction, vc *VelocityCounter) (bool, RiskLevel) {
			key := fmt.Sprintf("user:%s:tx", tx.UserID)
			count, _ := vc.Count(key, 2*time.Minute)
			if count > criticalCount {
				return true, RiskCritical
			}
			if count > highCount {
				return true, RiskHigh
			}
			return false, RiskLow
		},
	}
}
