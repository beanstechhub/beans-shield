package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLInjection_Detected(t *testing.T) {
	src := `package main

import "database/sql"

func getUser(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	findings := scanSource(t, src)
	assertHasFinding(t, findings, "BSEC-001", SeverityCritical)
}

func TestSQLInjection_ParameterizedSafe(t *testing.T) {
	src := `package main

import "database/sql"

func getUser(db *sql.DB, name string) {
	db.Query("SELECT * FROM users WHERE name = $1", name)
}
`
	findings := scanSource(t, src)
	assertNoFinding(t, findings, "BSEC-001")
}

func TestHardcodedSecret_Detected(t *testing.T) {
	src := `package main

func connect() {
	password := "super_secret_123"
	_ = password
}
`
	findings := scanSource(t, src)
	assertHasFinding(t, findings, "BSEC-002", SeverityHigh)
}

func TestHardcodedSecret_EnvVarSafe(t *testing.T) {
	src := `package main

import "os"

func connect() {
	password := os.Getenv("DB_PASSWORD")
	_ = password
}
`
	findings := scanSource(t, src)
	assertNoFinding(t, findings, "BSEC-002")
}

func TestWeakCrypto_MD5(t *testing.T) {
	src := `package main

import "crypto/md5"

func hash(data []byte) []byte {
	h := md5.Sum(data)
	return h[:]
}
`
	findings := scanSource(t, src)
	assertHasFinding(t, findings, "BSEC-003", SeverityHigh)
}

func TestWeakCrypto_SHA256Safe(t *testing.T) {
	src := `package main

import "crypto/sha256"

func hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
`
	findings := scanSource(t, src)
	assertNoFinding(t, findings, "BSEC-003")
}

func TestInsecureTLS_SkipVerify(t *testing.T) {
	src := `package main

import "crypto/tls"

func connect() {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	_ = cfg
}
`
	findings := scanSource(t, src)
	assertHasFinding(t, findings, "BSEC-007", SeverityHigh)
}

func TestInsecureTLS_OldVersion(t *testing.T) {
	src := `package main

import "crypto/tls"

func connect() {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS10,
	}
	_ = cfg
}
`
	findings := scanSource(t, src)
	assertHasFinding(t, findings, "BSEC-007", SeverityHigh)
}

func TestRaceCondition_GoroutinePackageVar(t *testing.T) {
	src := `package main

var counter int

func increment() {
	go func() {
		counter++
	}()
}
`
	findings := scanSource(t, src)
	assertHasFinding(t, findings, "BSEC-005", SeverityMedium)
}

func TestScanDir_Integration(t *testing.T) {
	dir := t.TempDir()

	// Write a vulnerable file
	vuln := `package main

import "crypto/md5"

var secret = "hardcoded"

func main() {
	_ = md5.New()
	_ = secret
}
`
	err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(vuln), 0644)
	if err != nil {
		t.Fatal(err)
	}

	s := New()
	result, err := s.ScanDir(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if result.Files != 1 {
		t.Errorf("expected 1 file scanned, got %d", result.Files)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings in vulnerable code")
	}

	output := s.FormatFindings(result)
	if output == "" {
		t.Error("expected formatted output")
	}
}

// --- Helpers ---

func scanSource(t *testing.T, src string) []Finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.go")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	s := New()
	findings, err := s.ScanFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func assertHasFinding(t *testing.T, findings []Finding, id string, severity Severity) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id && f.Severity == severity {
			return
		}
	}
	t.Errorf("expected finding %s with severity %s, got %d findings: %v", id, severity, len(findings), findingIDs(findings))
}

func assertNoFinding(t *testing.T, findings []Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			t.Errorf("expected no finding %s, but found: %s", id, f.Title)
		}
	}
}

func findingIDs(findings []Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}
