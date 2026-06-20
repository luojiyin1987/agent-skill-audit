package scanner

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	RuleID   string
	Severity string
	Path     string
	Line     int
	Message  string
}

type rule struct {
	id       string
	severity string
	pattern  *regexp.Regexp
	message  string
	files    []string
}

var rules = []rule{
	{
		id:       "SKILL001",
		severity: "MEDIUM",
		pattern:  regexp.MustCompile(`(?i)(bypass|skip|disable).{0,40}(confirmation|permission|approval|safety)`),
		message:  "instruction may bypass confirmation or permissions",
		files:    []string{"agent", "skill", "prompt"},
	},
	{
		id:       "SKILL002",
		severity: "HIGH",
		pattern:  regexp.MustCompile(`(?i)(~/.ssh|\.env|\.npmrc|\.pypirc|\.git-credentials|id_rsa|id_ed25519|github_token|openai_api_key|anthropic_api_key)`),
		message:  "references sensitive file or secret name",
		files:    []string{"agent", "skill", "prompt", "workflow", "mcp"},
	},
	{
		id:       "SKILL003",
		severity: "HIGH",
		pattern:  regexp.MustCompile(`(?i)(curl|wget).{0,80}\|.{0,20}(sh|bash)`),
		message:  "contains remote script execution pattern",
		files:    []string{"agent", "skill", "prompt", "workflow"},
	},
	{
		id:       "SKILL004",
		severity: "HIGH",
		pattern:  regexp.MustCompile(`(?i)(crontab|systemctl\s+enable|launchctl|RunAtLoad|KeepAlive|\.bashrc|\.zshrc)`),
		message:  "references persistence or startup modification",
		files:    []string{"agent", "skill", "prompt", "workflow"},
	},
	{
		id:       "MCP001",
		severity: "HIGH",
		pattern:  regexp.MustCompile(`(?i)"command"\s*:\s*"(bash|sh|zsh|powershell|cmd)"`),
		message:  "MCP command exposes shell execution",
		files:    []string{"mcp"},
	},
	{
		id:       "MCP002",
		severity: "MEDIUM",
		pattern:  regexp.MustCompile(`(?i)"command"\s*:\s*"(npx|uvx)"`),
		message:  "MCP command uses package runner; verify version pinning and package trust",
		files:    []string{"mcp"},
	},
	{
		id:       "GHA001",
		severity: "HIGH",
		pattern:  regexp.MustCompile(`(?i)(curl|wget).{0,80}\|.{0,20}(sh|bash)`),
		message:  "workflow contains remote script execution pattern",
		files:    []string{"workflow"},
	},
	{
		id:       "GHA002",
		severity: "HIGH",
		pattern:  regexp.MustCompile(`(?i)permissions\s*:\s*write-all`),
		message:  "workflow grants write-all permissions",
		files:    []string{"workflow"},
	},
	{
		id:       "GHA003",
		severity: "HIGH",
		pattern:  regexp.MustCompile(`(?i)pull_request_target\s*:`),
		message:  "workflow uses pull_request_target; review untrusted PR handling",
		files:    []string{"workflow"},
	},
}

func Scan(root string) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		kind := fileKind(path)
		if kind == "" {
			return nil
		}

		fileFindings, err := scanFile(root, path, kind)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

func scanFile(root, path, kind string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, r := range rules {
			if !ruleApplies(r, kind) {
				continue
			}
			if r.pattern.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				findings = append(findings, Finding{
					RuleID:   r.id,
					Severity: r.severity,
					Path:     rel,
					Line:     lineNo,
					Message:  r.message,
				})
			}
		}
	}
	return findings, scanner.Err()
}

func ruleApplies(r rule, kind string) bool {
	for _, k := range r.files {
		if k == kind {
			return true
		}
	}
	return false
}

func fileKind(path string) string {
	normalized := filepath.ToSlash(path)
	base := strings.ToLower(filepath.Base(path))

	switch {
	case base == "agents.md" || base == "claude.md":
		return "agent"
	case strings.Contains(normalized, "/.cursor/rules/") || strings.Contains(normalized, "/.claude/") || strings.Contains(normalized, "/skills/") || strings.Contains(normalized, "/.skill/"):
		return "skill"
	case base == "mcp.json" || base == "claude_desktop_config.json":
		return "mcp"
	case strings.Contains(normalized, "/.github/workflows/") && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")):
		return "workflow"
	}
	return ""
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", "dist", "build":
		return true
	default:
		return false
	}
}
