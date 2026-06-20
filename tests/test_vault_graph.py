from __future__ import annotations

import json
from pathlib import Path

from security_kg.cli import main
from security_kg.vault.finding_graph import build_vault_graph


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_build_vault_graph_extracts_obsidian_security_edges(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    write(
        vault / "03 - Findings" / "Finding - Example remote context poisoning.md",
        """---
type: finding
target: Target - Example App
status: draft
severity: High
cvss_vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
cvss_score: 6.5
cvss_confidence: reviewed
cwe: CWE-94
tags:
  - prompt-injection
pr: https://github.com/example-org/example-repo/pull/123
repo: https://github.com/example-org/example-repo
---

# Finding

Links to [[Target - Example App]] and #remote-to-local.
""",
    )
    write(
        vault / "02 - Targets" / "Target - Example App.md",
        """---
type: target
repo: https://github.com/example-org/example-repo
---

# Target
""",
    )

    graph = build_vault_graph(vault)
    labels = {node.label for node in graph.nodes}
    relations = {(edge.source, edge.target, edge.relation) for edge in graph.edges}

    assert "Finding - Example remote context poisoning" in labels
    assert "Target - Example App" in labels
    assert "#prompt-injection" in labels
    assert "#remote-to-local" in labels
    assert "CWE-94" in labels
    assert "example-org/example-repo#123" in labels
    finding = next(
        node for node in graph.nodes if node.label == "Finding - Example remote context poisoning"
    )
    assert finding.attrs["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    assert finding.attrs["cvss_score"] == 6.5
    assert finding.attrs["cvss_confidence"] == "reviewed"
    assert any(relation == "raised-pr" for _, _, relation in relations)


def test_cli_writes_obsidian_artifacts(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    write(
        vault / "03 - Findings" / "Finding - Example.md",
        """---
type: finding
tags: [ssrf]
---

[[Target - Example]] CWE-918 https://github.com/acme/example/pull/1
""",
    )
    write(vault / "02 - Targets" / "Target - Example.md", "---\ntype: target\n---\n")

    assert main(["vault-graph", "--vault", str(vault)]) == 0

    graph_json = vault / "99 - Graph" / "vulnweave-graph.json"
    canvas = vault / "99 - Graph" / "VulnWeave Graph.canvas"
    dashboard = vault / "99 - Graph" / "VulnWeave Graph.md"
    assert graph_json.exists()
    assert canvas.exists()
    assert dashboard.exists()
    parsed = json.loads(graph_json.read_text(encoding="utf-8"))
    assert parsed["nodes"]
    assert parsed["edges"]
    assert "```dataview" in dashboard.read_text(encoding="utf-8")
