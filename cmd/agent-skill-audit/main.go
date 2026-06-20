package main

import (
	"fmt"
	"os"

	"github.com/luojiyin1987/agent-skill-audit/internal/scanner"
)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	findings, err := scanner.Scan(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	for _, finding := range findings {
		fmt.Printf("%-7s %-8s %s:%d: %s\n", finding.Severity, finding.RuleID, finding.Path, finding.Line, finding.Message)
	}
}
