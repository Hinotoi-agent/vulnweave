# VulnWeave

**VulnWeave** is a local-first vulnerability research graph for people who review source code, prove security findings, and keep a long-running finding vault.

It connects two parts of security research that usually live in different places:

1. **Code evidence** — security-relevant facts extracted from a source repository: commands, scope/tenant intent, direct-load sinks, and invariant violations.
2. **Research memory** — Obsidian finding notes, targets, CWEs, tags, PRs, CVEs, and duplicate/variant relationships.

The goal is not to replace manual review. VulnWeave gives reviewers a graph-shaped workbench: map a repo, surface candidate invariants, prove or reject the candidate, then keep the finding connected to prior work so duplicate checks and variant hunting become easier over time.

## Why this exists

Security findings are rarely isolated facts. A useful report usually depends on a chain like:

```text
entry point -> trust boundary -> identity/scope assumption -> sensitive sink -> proof -> patch/report history
```

Most tools lose that context:

- SAST tools find noisy syntax patterns but do not know your prior duplicate decisions.
- Notes capture human judgment but are hard to query across repos, CWEs, PRs, and variants.
- PRs and disclosures record outcomes but are disconnected from source-level evidence.

VulnWeave tries to make that chain explicit and reusable.

## What VulnWeave can do today

### Source repository graph

`vulnweave map` walks a source tree and emits a small security-relevant graph. The current MVP recognizes patterns such as:

- command/control-plane registrations like `CommandSpec(name="/resume", remote_invocable=True)`
- actor/scope construction that mentions fields such as `sender`, `user`, or `tenant`
- direct object/session load sinks such as `load_by_id`, `get_by_id`, and `read_by_id`
- provider endpoint overrides, credential sources, HTTP request sinks, and endpoint validation guards
- path validation guards near filesystem write/extract sinks for symlink/TOCTOU review
- invariants such as remote control-plane command + scoped session intent + global direct-load sink

### Candidate review

`vulnweave candidates` reads either a source repo or a persisted graph directory and prints review candidates with supporting evidence. These are **not automatic vulnerability claims**; they are structured prompts for manual proof.

### Candidate-to-finding export

`vulnweave export-finding` bridges source candidates into Obsidian finding notes. It takes a candidate ID, writes a draft note with frontmatter, evidence, proof strategy, duplicate-check checklist, and patch/disclosure placeholders, then that note can be folded into `vulnweave vault-graph`.

### Finding-vault graph

`vulnweave vault-graph` scans an Obsidian vault and writes graph artifacts that help with:

- duplicate checks before opening a new issue or PR
- sibling/variant hunting across repos and bug classes
- coverage review by target, CWE, CVE, tag, or disclosure status
- keeping public PRs, notes, and target pages connected

The vault scanner reads normal Markdown plus optional YAML frontmatter. It extracts:

- finding notes and target notes
- wikilinks and hashtags
- CWE/CVE mentions
- GitHub repository and pull request URLs
- frontmatter fields such as `type`, `target`, `status`, `severity`, `cwe`, `tags`, `pr`, and `repo`

## Installation

For local development:

```bash
git clone https://github.com/Hinotoi-agent/vulnweave
cd vulnweave
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
vulnweave --help
```

The old `security-kg` command is kept as a compatibility alias for now:

```bash
security-kg --help
```

If you only want to run from a checkout without installing it:

```bash
PYTHONPATH=src python -m security_kg.cli --help
```

## Quick start

Run the bundled smoke fixture:

```bash
vulnweave map examples/remote_resume_drift --out /tmp/vulnweave-smoke
vulnweave candidates /tmp/vulnweave-smoke
vulnweave vault-graph --vault examples/vault --dry-run
vulnweave doctor --repo examples/remote_resume_drift --graph /tmp/vulnweave-smoke --vault examples/vault
```

You should see a mapped graph summary, at least one invariant-backed candidate from the fixture, a vault graph dry-run summary, and passing doctor checks.

## Source repo workflow

Map a repository and print a short summary:

```bash
vulnweave map /path/to/repo
```

Persist the graph for later review:

```bash
vulnweave map /path/to/repo --out /path/to/repo/.vulnweave
```

Find candidates from either a live repo path or a persisted graph:

```bash
vulnweave candidates /path/to/repo
vulnweave candidates /path/to/repo/.vulnweave
```

Emit machine-readable output:

```bash
vulnweave map /path/to/repo --json
vulnweave candidates /path/to/repo/.vulnweave --json
```

Export a candidate into a vault finding note:

```bash
vulnweave export-finding /path/to/repo/.vulnweave \
  --candidate resume-load_by_id-3 \
  --vault /path/to/example-vault \
  --target "Target - Example App" \
  --repo-url https://github.com/example-org/example-repo
```

The exported note includes YAML frontmatter, the graph path, evidence, a proof strategy, duplicate-check checklist, reproduction placeholders, patch/PR notes, and disclosure/CVE notes.

A typical candidate review loop looks like:

```text
map repo
  -> inspect candidates
  -> read the exact source paths and functions in the evidence
  -> reproduce or reject the suspected trust-boundary drift
  -> search prior findings/PRs/CVEs for duplicates
  -> write a maintainer-safe patch or report
  -> add the finding to the vault
  -> rebuild the vault graph
```

## Obsidian finding-vault workflow

Build graph artifacts inside a vault:

```bash
vulnweave vault-graph \
  --vault "/path/to/example-vault" \
  --findings-dir "03 - Findings" \
  --targets-dir "02 - Targets" \
  --output-dir "99 - Graph"
```

Dry run without writing files:

```bash
vulnweave vault-graph --vault /path/to/example-vault --dry-run
```

Print duplicate, stale-draft, missing-field, and variant-hunting hints:

```bash
vulnweave vault-insights --vault /path/to/example-vault
```

The command writes:

- `vulnweave-graph.json` — machine-readable graph for scripts, dashboards, or later importers
- `VulnWeave Graph.canvas` — Obsidian Canvas view of findings, targets, tags, CWEs, CVEs, repos, and PRs
- `VulnWeave Graph.md` — dashboard note with summary counts, links, and Dataview helpers

## Suggested note conventions

VulnWeave works with ordinary Markdown, but it gets more useful when findings use predictable frontmatter:

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

The body can use normal Obsidian links and tags:

```markdown
Links to [[Target - Example App]] and #remote-to-local.
Related class: CWE-94.
Possible duplicate: https://github.com/example-org/example-repo/pull/123
```

Recommended finding sections:

- **Boundary** — who controls the input and what trust boundary is crossed?
- **Invariant** — what security property should have held?
- **Evidence** — source paths, functions, graph nodes, logs, or screenshots.
- **Proof strategy** — the smallest safe repro needed to confirm impact.
- **Duplicate check** — related issues, PRs, CVEs, advisories, and prior notes.
- **Patch/report notes** — maintainer-safe framing and remediation direction.

## End-to-end workflow

```text
source repo
  -> vulnweave map
  -> vulnweave candidates
  -> local proof / duplicate check / patch
  -> vault finding note
  -> vulnweave vault-graph
  -> Obsidian duplicate, coverage, and variant review
```

## Output model

VulnWeave currently uses simple JSON/JSONL artifacts so the data is easy to inspect and script:

- `meta.json` — graph metadata and source root, including `schema_version: vulnweave.graph.v1`
- `nodes.jsonl` — one graph node per line
- `edges.jsonl` — one graph edge per line
- `vulnweave-graph.json` — merged vault graph export with `schema_version: vulnweave.vault_graph.v1`

JSON candidate output uses `schema_version: vulnweave.candidates.v1`. This keeps the tool local-first and avoids requiring a database while the schema is still evolving.

## Doctor checks

Use `doctor` to check local paths and expected graph/vault structure:

```bash
vulnweave doctor --repo /path/to/repo --graph /path/to/repo/.vulnweave --vault /path/to/example-vault
```

## Development

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check src tests examples
python -m compileall -q src tests examples
```

CI runs the same core checks on Python 3.9 and 3.12.

## Design principles

- **Local-first:** source repos and vaults stay on your machine unless you choose to publish results.
- **Evidence over claims:** candidates should point to concrete paths, symbols, and relations.
- **Human-in-the-loop:** the tool supports proof and reporting; it does not declare CVEs for you.
- **Graph-shaped memory:** every finding should become easier to compare with previous findings.
- **Plain files:** JSONL and Markdown first, database later only if the workflow needs it.

## Roadmap

Near-term:

- Improve interprocedural reachability and framework-specific handler mapping.
- Add more language frontends beyond Python.
- Add confidence scoring and suppression/allowlist support for known-safe patterns.
- Add richer vault aging/status analytics and optional GitHub PR status hydration.

Longer-term:

- Interactive graph dashboard.
- Proof-skeleton generation from candidate evidence.
- Cross-repo bug-class clustering.
- Import/export bridges for SARIF, GitHub issues, and disclosure trackers.

## Status

VulnWeave is an early MVP. Use it as a research assistant and workflow scaffold, not as a complete scanner.
