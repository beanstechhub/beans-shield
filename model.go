package shield

import (
	"fmt"
	"os"
)

type Scorer interface {
	Score(features []float64) float64
}

func WithScorer(s Scorer, weight float64) Option {
	return func(sh *Shield) {
		sh.scorer = s
		sh.scorerWeight = weight
	}
}

func blendScores(ruleScore float64, mlScore float64, weight float64) float64 {
	return ruleScore*(1-weight) + mlScore*10*weight
}

type ThresholdScorer struct {
	Threshold float64
}

func (ts *ThresholdScorer) Score(features []float64) float64 {
	if len(features) == 0 {
		return 0.0
	}
	score := 0.0
	if features[0] > ts.Threshold {
		score += 0.3
	}
	if len(features) > 10 {
		score += features[10] * 0.1
	}
	if len(features) > 11 {
		score += features[11] * 0.05
	}
	if len(features) > 13 && features[13] > 2.0 {
		score += 0.2
	}
	if len(features) > 12 {
		score += features[12] * 0.15
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

type ONNXScorer struct {
	ModelPath string
	model     []byte
}

func NewONNXScorer(modelPath string) (*ONNXScorer, error) {
	data, err := os.ReadFile(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ONNX model: %w", err)
	}
	return &ONNXScorer{
		ModelPath: modelPath,
		model:     data,
	}, nil
}

func (o *ONNXScorer) Score(features []float64) float64 {
	_ = o.model
	_ = features
	return 0.5
}
