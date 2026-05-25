from __future__ import annotations

import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from security_kg.invariants import find_candidates
from security_kg.io import is_graph_dir, read_graph_jsonl
from security_kg.schema import Candidate, Graph


def export_candidate_note(
    graph: Graph,
    candidate_id: str,
    vault: str | Path,
    target: str,
    repo_url: str | None = None,
    status: str = "draft",
    findings_dir: str = "03 - Findings",
    overwrite: bool = False,
) -> Path:
    candidate = get_candidate(graph, candidate_id)
    vault_path = _existing_vault_path(vault)
    out_dir = _findings_output_dir(vault_path, findings_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    note_path = (
        out_dir / f"Finding - {slug_title(graph.root.name)} - {slug_title(candidate.title)}.md"
    )
    if note_path.exists() and not overwrite:
        raise FileExistsError(f"finding note already exists: {note_path}")
    note_path.write_text(
        render_candidate_note(candidate, graph, target=target, repo_url=repo_url, status=status),
        encoding="utf-8",
    )
    return note_path


def export_candidate_from_graph_dir(
    graph_dir: str | Path,
    candidate_id: str,
    vault: str | Path,
    target: str,
    repo_url: str | None = None,
    status: str = "draft",
    findings_dir: str = "03 - Findings",
    overwrite: bool = False,
) -> Path:
    if not is_graph_dir(graph_dir):
        raise FileNotFoundError(f"not a VulnWeave graph directory: {graph_dir}")
    graph = read_graph_jsonl(graph_dir)
    return export_candidate_note(
        graph=graph,
        candidate_id=candidate_id,
        vault=vault,
        target=target,
        repo_url=repo_url,
        status=status,
        findings_dir=findings_dir,
        overwrite=overwrite,
    )


def get_candidate(graph: Graph, candidate_id: str) -> Candidate:
    candidates = find_candidates(graph)
    for candidate in candidates:
        if candidate.id == candidate_id:
            return candidate
    available = ", ".join(candidate.id for candidate in candidates) or "none"
    raise ValueError(f"candidate not found: {candidate_id}; available: {available}")


def render_candidate_note(
    candidate: Candidate,
    graph: Graph,
    target: str,
    repo_url: str | None = None,
    status: str = "draft",
) -> str:
    tags = ["vulnweave", candidate.pattern]
    frontmatter: dict[str, Any] = {
        "type": "finding",
        "status": status,
        "severity": candidate.severity_hint.title(),
        "target": target,
        "repo": repo_url or str(graph.root),
        "pattern": candidate.pattern,
        "generated_by": "vulnweave",
        "candidate_id": candidate.id,
        "tags": tags,
    }
    yaml = _yaml(frontmatter)
    graph_path = "\n".join(f"{index}. {item}" for index, item in enumerate(candidate.graph_path, 1))
    evidence = "\n".join(f"- {item}" for item in candidate.evidence)
    proof = "\n".join(f"- [ ] {item}" for item in candidate.proof_strategy)
    return f"""---
{yaml}---

# Finding - {candidate.title}

Linked target: [[{target}]]

## Candidate summary

- Candidate ID: `{candidate.id}`
- Pattern: `{candidate.pattern}`
- Severity hint: **{candidate.severity_hint}**
- Boundary: {candidate.boundary}
- Source root: `{graph.root}`

## Violated invariant

{candidate.violated_invariant}

## Graph path

{graph_path}

## Evidence

{evidence}

## Proof strategy

{proof}

## Duplicate check

- [ ] Search this vault for the same target, repo, CWE, and pattern.
- [ ] Search open and closed GitHub issues/PRs for matching reports or fixes.
- [ ] Search advisories, CVEs, release notes, and changelogs for the same root cause.
- [ ] Record the closest siblings and why this finding is or is not a duplicate.

## Reproduction notes

- [ ] Minimal safe repro created.
- [ ] Expected vulnerable behavior documented.
- [ ] Fixed/expected behavior documented.

## Patch / PR notes

- [ ] Remediation direction identified.
- [ ] Regression test added or planned.
- [ ] Maintainer-facing wording avoids overstating impact beyond the proof.

## Disclosure / CVE notes

- [ ] Disclosure path selected if needed.
- [ ] CVE/VulnCheck request decision recorded if applicable.
"""


def _existing_vault_path(vault: str | Path) -> Path:
    vault_path = Path(vault).expanduser().resolve()
    if not vault_path.exists():
        raise FileNotFoundError(f"vault does not exist: {vault_path}")
    if not vault_path.is_dir():
        raise NotADirectoryError(f"vault is not a directory: {vault_path}")
    return vault_path


def _findings_output_dir(vault_path: Path, findings_dir: str) -> Path:
    requested = Path(findings_dir).expanduser()
    if requested.is_absolute():
        raise ValueError("findings_dir must be relative to the vault")
    if any(part == ".." for part in requested.parts):
        raise ValueError("findings_dir must not contain '..' path segments")
    out_dir = (vault_path / requested).resolve()
    if out_dir != vault_path and vault_path not in out_dir.parents:
        raise ValueError(f"findings_dir escapes the vault: {findings_dir}")
    return out_dir


def slug_title(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", " ", value).strip()
    return " ".join(word.capitalize() for word in text.split()) or "Candidate"


def _yaml(data: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, list):
            lines.append(f"{key}:")
            lines.extend(f"  - {item}" for item in value)
        elif value is None:
            lines.append(f"{key}: null")
        else:
            rendered = str(value).replace('"', '\\"')
            lines.append(f'{key}: "{rendered}"')
    return "\n".join(lines) + "\n"


def candidate_as_dict(candidate: Candidate) -> dict[str, Any]:
    return asdict(candidate)
