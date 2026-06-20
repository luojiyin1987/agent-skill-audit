# agent-skill-audit

Audit AI Agent, Skill, MCP, and GitHub Actions projects for dangerous permissions, shell execution, secret exposure, and supply-chain risks.

`agent-skill-audit` focuses on emerging risks introduced by AI coding agents, Claude skills, Cursor rules, MCP servers, and workflow automation.

## What it checks

The first version focuses on local repository scanning:

- Agent and skill instruction files such as `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/*`, `.claude/*`, and `skills/*`
- MCP configuration files such as `mcp.json` and `claude_desktop_config.json`
- GitHub Actions workflows under `.github/workflows/*.yml`
- Dangerous shell patterns such as `curl | sh`, `wget | bash`, `sudo`, `chmod +x`, and persistence changes
- Sensitive file access patterns such as `~/.ssh`, `.env`, `.npmrc`, `.git-credentials`, and API tokens

## Usage

```bash
go run ./cmd/agent-skill-audit .
```

Example output:

```text
HIGH    SKILL002  AGENTS.md: references sensitive file ~/.ssh
HIGH    SKILL003  AGENTS.md: contains remote script execution pattern curl | bash
HIGH    MCP001    mcp.json: MCP command uses shell
HIGH    GHA001    .github/workflows/ci.yml: workflow contains curl | bash
```

## Rule categories

- `SKILL`: Agent, skill, and prompt instruction risks
- `MCP`: MCP server and local tool exposure risks
- `GHA`: GitHub Actions workflow risks

## Status

Early-stage project. The first goal is a small, reliable local scanner before adding SARIF, GitHub Action integration, and PR comments.
