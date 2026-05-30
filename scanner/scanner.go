package scanner

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Category string

const (
	CategoryInjection    Category = "injection"
	CategoryAuth         Category = "authentication"
	CategoryCrypto       Category = "cryptography"
	CategoryRaceCondition Category = "race_condition"
	CategoryMemory       Category = "memory_safety"
	CategoryInput        Category = "input_validation"
	CategoryConfig       Category = "configuration"
	CategoryInfoLeak     Category = "information_leak"
)

type Finding struct {
	ID          string   `json:"id"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Snippet     string   `json:"snippet,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type ScanResult struct {
	Target      string    `json:"target"`
	Files       int       `json:"files_scanned"`
	Findings    []Finding `json:"findings"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
}

type VulnRule interface {
	ID() string
	Name() string
	Category() Category
	Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding
}

type Scanner struct {
	rules   []VulnRule
	mu      sync.Mutex
}

type Option func(*Scanner)

func WithRules(rules ...VulnRule) Option {
	return func(s *Scanner) { s.rules = append(s.rules, rules...) }
}

func New(opts ...Option) *Scanner {
	s := &Scanner{
		rules: DefaultRules(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func DefaultRules() []VulnRule {
	return []VulnRule{
		&SQLInjectionRule{},
		&HardcodedSecretRule{},
		&WeakCryptoRule{},
		&UnsafeExecRule{},
		&RaceConditionRule{},
		&UnvalidatedRedirectRule{},
		&InsecureTLSRule{},
		&ErrorInfoLeakRule{},
	}
}

func (s *Scanner) ScanDir(ctx context.Context, dir string) (*ScanResult, error) {
	result := &ScanResult{Target: dir}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "node_modules" || base == ".git" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		findings, err := s.scanFile(path)
		if err != nil {
			return nil
		}
		s.mu.Lock()
		result.Findings = append(result.Findings, findings...)
		result.Files++
		s.mu.Unlock()
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, f := range result.Findings {
		switch f.Severity {
		case SeverityCritical:
			result.Critical++
		case SeverityHigh:
			result.High++
		case SeverityMedium:
			result.Medium++
		case SeverityLow:
			result.Low++
		}
	}

	return result, nil
}

func (s *Scanner) ScanFile(ctx context.Context, path string) ([]Finding, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.scanFile(path)
}

func (s *Scanner) scanFile(path string) ([]Finding, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, rule := range s.rules {
		ruleFindings := rule.Scan(file, fset, src)
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

func (s *Scanner) FormatFindings(result *ScanResult) string {
	if len(result.Findings) == 0 {
		return fmt.Sprintf("Scanned %d files in %s — no vulnerabilities found.", result.Files, result.Target)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("beans-shield scanner: %d findings in %d files\n", len(result.Findings), result.Files))
	b.WriteString(fmt.Sprintf("  Critical: %d | High: %d | Medium: %d | Low: %d\n\n", result.Critical, result.High, result.Medium, result.Low))

	for i, f := range result.Findings {
		b.WriteString(fmt.Sprintf("[%d] %s (%s)\n", i+1, f.Title, f.Severity))
		b.WriteString(fmt.Sprintf("    File: %s:%d\n", f.File, f.Line))
		b.WriteString(fmt.Sprintf("    Category: %s\n", f.Category))
		if f.CWE != "" {
			b.WriteString(fmt.Sprintf("    CWE: %s\n", f.CWE))
		}
		b.WriteString(fmt.Sprintf("    %s\n", f.Description))
		if f.Remediation != "" {
			b.WriteString(fmt.Sprintf("    Fix: %s\n", f.Remediation))
		}
		b.WriteString("\n")
	}

	return b.String()
}
