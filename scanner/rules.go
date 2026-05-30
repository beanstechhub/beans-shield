package scanner

import (
	"go/ast"
	"go/token"
	"strings"
)

// SQLInjectionRule detects string concatenation in SQL queries.
type SQLInjectionRule struct{}

func (r *SQLInjectionRule) ID() string       { return "BSEC-001" }
func (r *SQLInjectionRule) Name() string     { return "SQL Injection" }
func (r *SQLInjectionRule) Category() Category { return CategoryInjection }

func (r *SQLInjectionRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		methodName := sel.Sel.Name
		sqlMethods := []string{"Query", "QueryRow", "QueryContext", "QueryRowContext", "Exec", "ExecContext", "Prepare", "PrepareContext"}
		isSQLMethod := false
		for _, m := range sqlMethods {
			if methodName == m {
				isSQLMethod = true
				break
			}
		}
		if !isSQLMethod || len(call.Args) == 0 {
			return true
		}

		firstArg := call.Args[0]
		if isContextArg(firstArg) && len(call.Args) > 1 {
			firstArg = call.Args[1]
		}

		if containsStringConcat(firstArg) || containsSprintfWithoutParams(firstArg, call.Args) {
			pos := fset.Position(call.Pos())
			snippet := getSnippet(src, pos.Line)
			findings = append(findings, Finding{
				ID:          r.ID(),
				File:        pos.Filename,
				Line:        pos.Line,
				Column:      pos.Column,
				Severity:    SeverityCritical,
				Category:    CategoryInjection,
				Title:       "Potential SQL injection via string concatenation",
				Description: "SQL query built using string concatenation or fmt.Sprintf without parameterized queries. User-controlled input may be injected.",
				Snippet:     snippet,
				CWE:         "CWE-89",
				Remediation: "Use parameterized queries with $1, $2 placeholders instead of string interpolation.",
			})
		}

		return true
	})

	return findings
}

// HardcodedSecretRule detects hardcoded passwords, tokens, and keys.
type HardcodedSecretRule struct{}

func (r *HardcodedSecretRule) ID() string       { return "BSEC-002" }
func (r *HardcodedSecretRule) Name() string     { return "Hardcoded Secret" }
func (r *HardcodedSecretRule) Category() Category { return CategoryConfig }

func (r *HardcodedSecretRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	sensitivePatterns := []string{"password", "passwd", "secret", "api_key", "apikey", "token", "private_key", "privatekey"}

	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}

			nameLower := strings.ToLower(ident.Name)
			isSensitive := false
			for _, pattern := range sensitivePatterns {
				if strings.Contains(nameLower, pattern) {
					isSensitive = true
					break
				}
			}
			if !isSensitive || i >= len(assign.Rhs) {
				continue
			}

			lit, ok := assign.Rhs[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			if len(lit.Value) <= 4 {
				continue
			}

			pos := fset.Position(assign.Pos())
			findings = append(findings, Finding{
				ID:          r.ID(),
				File:        pos.Filename,
				Line:        pos.Line,
				Column:      pos.Column,
				Severity:    SeverityHigh,
				Category:    CategoryConfig,
				Title:       "Hardcoded secret in source code",
				Description: "Variable '" + ident.Name + "' appears to contain a hardcoded secret value.",
				Snippet:     getSnippet(src, pos.Line),
				CWE:         "CWE-798",
				Remediation: "Load secrets from environment variables or a secret manager (e.g., GCP Secret Manager, HashiCorp Vault).",
			})
		}
		return true
	})

	return findings
}

// WeakCryptoRule detects usage of broken cryptographic algorithms.
type WeakCryptoRule struct{}

func (r *WeakCryptoRule) ID() string       { return "BSEC-003" }
func (r *WeakCryptoRule) Name() string     { return "Weak Cryptography" }
func (r *WeakCryptoRule) Category() Category { return CategoryCrypto }

func (r *WeakCryptoRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	weakImports := map[string]string{
		"crypto/md5":    "MD5 is cryptographically broken (collision attacks). Use SHA-256 or SHA-3.",
		"crypto/sha1":   "SHA-1 is deprecated for security purposes (SHAttered attack). Use SHA-256 or SHA-3.",
		"crypto/des":    "DES/3DES is deprecated. Use AES-256-GCM.",
		"crypto/rc4":    "RC4 is broken. Use AES-256-GCM or ChaCha20-Poly1305.",
	}

	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		if msg, weak := weakImports[path]; weak {
			pos := fset.Position(imp.Pos())
			findings = append(findings, Finding{
				ID:          r.ID(),
				File:        pos.Filename,
				Line:        pos.Line,
				Column:      pos.Column,
				Severity:    SeverityHigh,
				Category:    CategoryCrypto,
				Title:       "Usage of weak/broken cryptographic algorithm",
				Description: msg,
				Snippet:     getSnippet(src, pos.Line),
				CWE:         "CWE-327",
				Remediation: "Replace with a modern algorithm: AES-256-GCM, SHA-256, Ed25519, or X25519.",
			})
		}
	}

	return findings
}

// UnsafeExecRule detects command injection via os/exec with user input.
type UnsafeExecRule struct{}

func (r *UnsafeExecRule) ID() string       { return "BSEC-004" }
func (r *UnsafeExecRule) Name() string     { return "Command Injection" }
func (r *UnsafeExecRule) Category() Category { return CategoryInjection }

func (r *UnsafeExecRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext" {
			return true
		}

		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "exec" {
			for _, arg := range call.Args {
				if containsStringConcat(arg) || isVariable(arg) {
					pos := fset.Position(call.Pos())
					findings = append(findings, Finding{
						ID:          r.ID(),
						File:        pos.Filename,
						Line:        pos.Line,
						Column:      pos.Column,
						Severity:    SeverityCritical,
						Category:    CategoryInjection,
						Title:       "Potential command injection",
						Description: "exec.Command called with variable arguments that may contain user input.",
						Snippet:     getSnippet(src, pos.Line),
						CWE:         "CWE-78",
						Remediation: "Validate and sanitize all arguments. Use allowlists for permitted commands. Never pass user input directly to exec.",
					})
					break
				}
			}
		}

		return true
	})

	return findings
}

// RaceConditionRule detects shared state accessed without synchronization.
type RaceConditionRule struct{}

func (r *RaceConditionRule) ID() string       { return "BSEC-005" }
func (r *RaceConditionRule) Name() string     { return "Race Condition" }
func (r *RaceConditionRule) Category() Category { return CategoryRaceCondition }

func (r *RaceConditionRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	// Detect goroutines accessing package-level variables without mutex
	var packageVars []string
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.VAR {
			continue
		}
		for _, spec := range genDecl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name != "_" {
					packageVars = append(packageVars, name.Name)
				}
			}
		}
	}

	if len(packageVars) == 0 {
		return findings
	}

	ast.Inspect(file, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}

		// Check if goroutine body references package-level vars
		ast.Inspect(goStmt.Call, func(inner ast.Node) bool {
			ident, ok := inner.(*ast.Ident)
			if !ok {
				return true
			}
			for _, pv := range packageVars {
				if ident.Name == pv {
					pos := fset.Position(goStmt.Pos())
					findings = append(findings, Finding{
						ID:          r.ID(),
						File:        pos.Filename,
						Line:        pos.Line,
						Column:      pos.Column,
						Severity:    SeverityMedium,
						Category:    CategoryRaceCondition,
						Title:       "Potential race condition on package variable",
						Description: "Goroutine accesses package-level variable '" + pv + "' without visible synchronization.",
						Snippet:     getSnippet(src, pos.Line),
						CWE:         "CWE-362",
						Remediation: "Protect shared state with sync.Mutex, sync.RWMutex, or use channels.",
					})
					return false
				}
			}
			return true
		})

		return true
	})

	return findings
}

// UnvalidatedRedirectRule detects HTTP redirects using user-controlled input.
type UnvalidatedRedirectRule struct{}

func (r *UnvalidatedRedirectRule) ID() string       { return "BSEC-006" }
func (r *UnvalidatedRedirectRule) Name() string     { return "Unvalidated Redirect" }
func (r *UnvalidatedRedirectRule) Category() Category { return CategoryInput }

func (r *UnvalidatedRedirectRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		if sel.Sel.Name != "Redirect" {
			return true
		}

		// Check if redirect URL comes from request parameters
		for _, arg := range call.Args {
			if callsRequestParam(arg) {
				pos := fset.Position(call.Pos())
				findings = append(findings, Finding{
					ID:          r.ID(),
					File:        pos.Filename,
					Line:        pos.Line,
					Column:      pos.Column,
					Severity:    SeverityMedium,
					Category:    CategoryInput,
					Title:       "Unvalidated redirect using user input",
					Description: "HTTP redirect URL derived from request parameters without validation.",
					Snippet:     getSnippet(src, pos.Line),
					CWE:         "CWE-601",
					Remediation: "Validate redirect URLs against an allowlist of permitted domains.",
				})
				break
			}
		}

		return true
	})

	return findings
}

// InsecureTLSRule detects insecure TLS configurations.
type InsecureTLSRule struct{}

func (r *InsecureTLSRule) ID() string       { return "BSEC-007" }
func (r *InsecureTLSRule) Name() string     { return "Insecure TLS Configuration" }
func (r *InsecureTLSRule) Category() Category { return CategoryCrypto }

func (r *InsecureTLSRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	ast.Inspect(file, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}

		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			return true
		}

		if ident.Name == "InsecureSkipVerify" {
			if lit, ok := kv.Value.(*ast.Ident); ok && lit.Name == "true" {
				pos := fset.Position(kv.Pos())
				findings = append(findings, Finding{
					ID:          r.ID(),
					File:        pos.Filename,
					Line:        pos.Line,
					Column:      pos.Column,
					Severity:    SeverityHigh,
					Category:    CategoryCrypto,
					Title:       "TLS certificate verification disabled",
					Description: "InsecureSkipVerify=true disables certificate validation, enabling man-in-the-middle attacks.",
					Snippet:     getSnippet(src, pos.Line),
					CWE:         "CWE-295",
					Remediation: "Remove InsecureSkipVerify or set to false. Use proper CA certificates.",
				})
			}
		}

		if ident.Name == "MinVersion" {
			if sel, ok := kv.Value.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == "VersionTLS10" || sel.Sel.Name == "VersionTLS11" || sel.Sel.Name == "VersionSSL30" {
					pos := fset.Position(kv.Pos())
					findings = append(findings, Finding{
						ID:          r.ID(),
						File:        pos.Filename,
						Line:        pos.Line,
						Column:      pos.Column,
						Severity:    SeverityHigh,
						Category:    CategoryCrypto,
						Title:       "Outdated TLS version allowed",
						Description: "TLS 1.0/1.1 and SSL 3.0 have known vulnerabilities (POODLE, BEAST). Minimum should be TLS 1.2.",
						Snippet:     getSnippet(src, pos.Line),
						CWE:         "CWE-326",
						Remediation: "Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13.",
					})
				}
			}
		}

		return true
	})

	return findings
}

// ErrorInfoLeakRule detects detailed error messages exposed to users.
type ErrorInfoLeakRule struct{}

func (r *ErrorInfoLeakRule) ID() string       { return "BSEC-008" }
func (r *ErrorInfoLeakRule) Name() string     { return "Error Information Leak" }
func (r *ErrorInfoLeakRule) Category() Category { return CategoryInfoLeak }

func (r *ErrorInfoLeakRule) Scan(file *ast.File, fset *token.FileSet, src []byte) []Finding {
	var findings []Finding

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		// Detect http.Error(w, err.Error(), ...) patterns
		if sel.Sel.Name == "Error" {
			if len(call.Args) >= 2 {
				if isErrError(call.Args[1]) {
					pos := fset.Position(call.Pos())
					findings = append(findings, Finding{
						ID:          r.ID(),
						File:        pos.Filename,
						Line:        pos.Line,
						Column:      pos.Column,
						Severity:    SeverityLow,
						Category:    CategoryInfoLeak,
						Title:       "Internal error details exposed to client",
						Description: "Raw error message sent in HTTP response. May leak implementation details, stack traces, or database info.",
						Snippet:     getSnippet(src, pos.Line),
						CWE:         "CWE-209",
						Remediation: "Return generic error messages to clients. Log detailed errors server-side.",
					})
				}
			}
		}

		return true
	})

	return findings
}

// --- Helpers ---

func containsStringConcat(expr ast.Expr) bool {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	return bin.Op == token.ADD
}

func containsSprintfWithoutParams(expr ast.Expr, allArgs []ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if sel.Sel.Name == "Sprintf" && len(call.Args) > 1 {
		return true
	}
	return false
}

func isContextArg(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if ok && (ident.Name == "ctx" || ident.Name == "context") {
		return true
	}
	return false
}

func isVariable(expr ast.Expr) bool {
	_, ok := expr.(*ast.Ident)
	return ok
}

func isErrError(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Error"
}

func callsRequestParam(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if name == "FormValue" || name == "Query" || name == "Get" || name == "Param" {
			found = true
			return false
		}
		return true
	})
	return found
}

func getSnippet(src []byte, line int) string {
	lines := strings.Split(string(src), "\n")
	if line <= 0 || line > len(lines) {
		return ""
	}
	snippet := strings.TrimSpace(lines[line-1])
	if len(snippet) > 120 {
		snippet = snippet[:120] + "..."
	}
	return snippet
}
