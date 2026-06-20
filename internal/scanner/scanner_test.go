package scanner

import (
	"path/filepath"
	"testing"
)

func TestScanUnsafeAgentFixture(t *testing.T) {
	findings, err := Scan(filepath.Join("..", "..", "testdata", "unsafe-agent"))
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	wantRules := map[string]bool{
		"SKILL001": false,
		"SKILL002": false,
		"SKILL003": false,
		"SKILL004": false,
		"MCP001":   false,
		"MCP002":   false,
		"GHA001":   false,
		"GHA002":   false,
		"GHA003":   false,
	}

	for _, finding := range findings {
		if _, ok := wantRules[finding.RuleID]; ok {
			wantRules[finding.RuleID] = true
		}
	}

	for ruleID, found := range wantRules {
		if !found {
			t.Fatalf("expected rule %s to be reported; got findings: %#v", ruleID, findings)
		}
	}
}

func TestScanSafeAgentFixture(t *testing.T) {
	findings, err := Scan(filepath.Join("..", "..", "testdata", "safe-agent"))
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("expected no findings for safe fixture; got %#v", findings)
	}
}
