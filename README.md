# audit-axios

Scan local repos for vulnerable axios versions and patch interactively.

Targets [**CVE-2026-40175**](https://github.com/axios/axios/security/advisories/GHSA-fvcv-3m26-pcqx) — CRLF Header Injection leading to Request Smuggling & SSRF. CVSS 9.9, affects all axios < 1.15.0.

## Quick Start

```bash
npx audit-axios ~/Workspace ~/Projects
```

## Usage

```bash
# Interactive — checkbox select + bulk action
audit-axios ~/Workspace ~/Projects

# Scan only (CI-friendly, exit code 1 if vulnerable)
audit-axios --scan-only ~/Workspace

# Auto-patch everything
audit-axios --auto-patch ~/Workspace ~/Projects

# Custom minimum version
audit-axios --min-version 1.16.0 --target "^1.16.0" ~/Workspace
```

## Interactive Controls

| Key | Action |
|-----|--------|
| `space` | Toggle select/deselect |
| `a` | Select all |
| `n` | Deselect all |
| `j/k` or arrows | Navigate |
| `enter` | Confirm → choose action |
| `q` | Quit |

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--scan-only` | Report only, no prompts | — |
| `--auto-patch` | Patch all without prompting | — |
| `--min-version` | Minimum safe version | `1.15.0` |
| `--target` | Target version spec | `^1.15.0` |
| `--include-all` | Include IDE extensions, caches, and system dirs | — |

## Ignored by Default

IDE extensions (`.vscode`, `.cursor`, `.kiro`, etc.), package caches (`.npm`, `.yarn`), and system dirs are excluded from scans. Use `--include-all` to include them.

`node_modules` and `.git` are **always** excluded — nested dependencies should be fixed via [overrides/resolutions](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#overrides), not direct patching.

## Features

- Zero dependencies — Node.js built-ins only
- Auto-detects npm, yarn, pnpm (including `packageManager` field)
- Monorepo workspace-aware (pnpm-workspace.yaml, yarn workspaces)
- Scrollable checkbox UI with bulk actions
- Severity labels (CRITICAL / HIGH / MEDIUM) based on version gap
- CI mode with `--scan-only` (exit 1 on vulnerability found)

## License

MIT
