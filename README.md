# security-kg

`security-kg` is a lightweight, local-first security knowledge graph toolkit for source-code vulnerability review and Obsidian-based finding management.

It now combines two formerly separate workflows:

1. **Repo/code graph:** map source repositories into security-relevant facts and detect invariant-backed review candidates.
2. **Finding/vault graph:** scan an Obsidian security research vault and generate graph artifacts for duplicate checks, coverage review, variant hunting, and reporting context.

This is intentionally not a vulnerability oracle. It produces review candidates and research maps that still require local proof, duplicate checks, and maintainer-safe reporting.

## Current MVP

The source-code extractor detects:

- command registrations such as `CommandSpec(name='/resume', remote_invocable=True)`
- session-scope construction that includes actor fields such as `sender`, `user`, or `tenant`
- direct object/session load sinks such as `load_by_id`, `get_by_id`, and `read_by_id`
- a first invariant: remote control-plane command plus scoped session intent plus global direct-load sink

The vault graph builder detects from Obsidian Markdown:

- finding notes and target notes
- wikilinks and hashtags
- CWE/CVE mentions
- GitHub repository URLs and pull request URLs
- frontmatter fields such as `type`, `target`, `status`, `severity`, `cwe`, `tags`, `pr`, and `repo`

## Installation

For local development, install the package in editable mode with its development tools:

```bash
git clone https://github.com/Hinotoi-agent/security-kg
cd security-kg
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
security-kg --help
```

If you only want to run the CLI from a checkout without installing it, prefix commands with
`PYTHONPATH=src python -m security_kg.cli`.

## Source repo usage

Map a repository and print a summary:

```bash
security-kg map /path/to/repo
```

Map a repository and persist the graph for later review:

```bash
security-kg map /path/to/repo --out /path/to/repo/.security-kg
```

Find candidates either directly from the repo or from the persisted graph:

```bash
security-kg candidates /path/to/repo
security-kg candidates /path/to/repo/.security-kg
```

Emit machine-readable output:

```bash
security-kg map /path/to/repo --json
security-kg candidates /path/to/repo/.security-kg --json
```

Run the bundled generic smoke fixture:

```bash
security-kg map examples/remote_resume_drift --out /tmp/security-kg-smoke
security-kg candidates /tmp/security-kg-smoke
```

## Obsidian finding-vault usage

Build graph artifacts in a vault:

```bash
security-kg vault-graph \
  --vault "/path/to/example-vault" \
  --findings-dir "03 - Findings" \
  --targets-dir "02 - Targets" \
  --output-dir "99 - Graph"
```

Dry run without writing:

```bash
security-kg vault-graph --vault /path/to/example-vault --dry-run
```

The command writes:

- `security-finding-graph.json` — machine-readable graph for custom dashboards or scripts
- `Security Finding Graph.canvas` — Obsidian Canvas view of findings, targets, tags, CWEs, and related notes
- `Security Finding Graph.md` — Obsidian dashboard note with wikilinks, summary counts, and Dataview snippets

## Finding note conventions

The scanner works with normal Obsidian Markdown. It gets better if notes use YAML frontmatter:

```yaml
---
type: finding
target: Target - Example App
status: draft
severity: High
cwe: CWE-94
tags:
  - prompt-injection
  - remote-to-local
pr: https://github.com/example-org/example-repo/pull/123
repo: https://github.com/example-org/example-repo
---
```

It also reads:

- Wikilinks: `[[Target - Example]]`
- Hashtags: `#prompt-injection`
- CVEs/CWEs in text: `CVE-2026-0001`, `CWE-94`
- GitHub URLs and PR URLs

## End-to-end workflow

```text
source repo
  -> security-kg map
  -> security-kg candidates
  -> local proof / duplicate check / patch
  -> vault finding note
  -> security-kg vault-graph
  -> Obsidian duplicate, coverage, and variant review
```

## Development

```bash
python3 -m pytest -q
python3 -m ruff check src tests examples
python3 -m compileall src tests examples
```

## Roadmap

- Add route/webhook extractors.
- Add list-filter/direct-load drift detection.
- Add bearer handle ownership checks for jobs, processes, sessions, and artifacts.
- Add deterministic proof-skeleton generation.
- Add candidate-to-vault-note export.
- Add richer vault graph pivots for duplicate posture and sibling variants.
