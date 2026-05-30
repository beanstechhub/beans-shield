package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AIScanner uses Claude to perform deep vulnerability analysis on code.
// It combines static rule findings with LLM-powered reasoning to reduce
// false positives and discover complex multi-step vulnerabilities that
// static analysis cannot detect (auth bypasses, logic flaws, TOCTOU, etc).
type AIScanner struct {
	apiKey  string
	model   string
	baseURL string
	client  *http.Client
}

type AIOption func(*AIScanner)

func WithModel(model string) AIOption {
	return func(a *AIScanner) { a.model = model }
}

func WithBaseURL(url string) AIOption {
	return func(a *AIScanner) { a.baseURL = url }
}

func NewAIScanner(apiKey string, opts ...AIOption) *AIScanner {
	a := &AIScanner{
		apiKey:  apiKey,
		model:   "claude-sonnet-4-6-20250514",
		baseURL: "https://api.anthropic.com",
		client:  &http.Client{Timeout: 120 * time.Second},
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func NewAIScannerFromEnv(opts ...AIOption) *AIScanner {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil
	}
	return NewAIScanner(key, opts...)
}

type AIFinding struct {
	Finding
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
	Exploitable bool   `json:"exploitable"`
}

type aiRequest struct {
	Model     string      `json:"model"`
	MaxTokens int         `json:"max_tokens"`
	System    string      `json:"system"`
	Messages  []aiMessage `json:"messages"`
}

type aiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

const systemPrompt = `You are a world-class security researcher specializing in finding vulnerabilities in Go code. Your task is to analyze source code and identify security vulnerabilities.

For each vulnerability found, respond with a JSON array of objects containing:
- "title": short description
- "severity": "critical", "high", "medium", or "low"
- "category": "injection", "authentication", "cryptography", "race_condition", "memory_safety", "input_validation", "configuration", or "information_leak"
- "line": approximate line number
- "description": detailed explanation of the vulnerability
- "cwe": the relevant CWE ID (e.g., "CWE-89")
- "exploitable": true/false - whether this is practically exploitable
- "confidence": 0.0-1.0 confidence score
- "reasoning": brief explanation of how an attacker would exploit this
- "remediation": specific fix recommendation

Focus on:
1. SQL injection, command injection, path traversal
2. Authentication/authorization bypasses
3. Race conditions and TOCTOU vulnerabilities
4. Cryptographic weaknesses
5. Logic flaws that bypass security controls
6. Information leaks (credentials, tokens, PII)
7. Unsafe deserialization
8. SSRF and unvalidated redirects

Only report findings you are >70% confident about. Respond with ONLY the JSON array, no other text.`

// AnalyzeFile sends source code to Claude for deep vulnerability analysis.
func (a *AIScanner) AnalyzeFile(ctx context.Context, path string, src []byte) ([]AIFinding, error) {
	if a == nil {
		return nil, fmt.Errorf("AI scanner not initialized (missing ANTHROPIC_API_KEY?)")
	}

	prompt := fmt.Sprintf("Analyze this Go source file for security vulnerabilities:\n\nFile: %s\n\n```go\n%s\n```", path, string(src))

	req := aiRequest{
		Model:     a.model,
		MaxTokens: 4096,
		System:    systemPrompt,
		Messages: []aiMessage{
			{Role: "user", Content: prompt},
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	var aiResp aiResponse
	if err := json.NewDecoder(resp.Body).Decode(&aiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(aiResp.Content) == 0 {
		return nil, nil
	}

	text := aiResp.Content[0].Text
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "```") {
		lines := strings.Split(text, "\n")
		if len(lines) > 2 {
			text = strings.Join(lines[1:len(lines)-1], "\n")
		}
	}

	var findings []AIFinding
	if err := json.Unmarshal([]byte(text), &findings); err != nil {
		return nil, fmt.Errorf("failed to parse AI findings: %w (response: %s)", err, text[:min(200, len(text))])
	}

	// Set file path on all findings
	for i := range findings {
		findings[i].File = path
		findings[i].ID = fmt.Sprintf("AI-%03d", i+1)
	}

	return findings, nil
}

// DeepScan combines static rules with AI-powered analysis for maximum coverage.
func (a *AIScanner) DeepScan(ctx context.Context, s *Scanner, dir string) (*ScanResult, []AIFinding, error) {
	staticResult, err := s.ScanDir(ctx, dir)
	if err != nil {
		return nil, nil, err
	}

	if a == nil {
		return staticResult, nil, nil
	}

	// AI scans the same files for deeper analysis
	var aiFindings []AIFinding
	files := listGoFiles(dir)

	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if len(src) > 50_000 {
			continue
		}

		findings, err := a.AnalyzeFile(ctx, f, src)
		if err != nil {
			continue
		}
		aiFindings = append(aiFindings, findings...)
	}

	return staticResult, aiFindings, nil
}

func listGoFiles(dir string) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return files
	}
	for _, e := range entries {
		if e.IsDir() {
			if e.Name() == "vendor" || e.Name() == ".git" || e.Name() == "node_modules" {
				continue
			}
			files = append(files, listGoFiles(dir+"/"+e.Name())...)
			continue
		}
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			files = append(files, dir+"/"+e.Name())
		}
	}
	return files
}
