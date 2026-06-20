from __future__ import annotations

import json
import math
from dataclasses import asdict
from pathlib import Path
from typing import Any

from security_kg.schema import Graph, Node

KIND_COLORS = {
    "finding": "1",
    "target": "2",
    "repo": "3",
    "pull_request": "4",
    "cwe": "5",
    "cve": "6",
    "tag": "7",
    "note": "0",
}


def write_vault_graph_json(graph: Graph, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": "vulnweave.vault_graph.v1",
        "root": str(graph.root),
        "nodes": [asdict(node) for node in sorted(graph.nodes, key=lambda n: n.id)],
        "edges": [asdict(edge) for edge in graph.edges],
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_canvas(graph: Graph, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    nodes = sorted(graph.nodes, key=lambda node: (node.kind, node.label))
    positions = _layout(nodes)
    canvas_nodes: list[dict[str, Any]] = []
    for node in nodes:
        x, y = positions[node.id]
        if node.path and node.kind in {"finding", "target", "note"}:
            canvas_node: dict[str, Any] = {
                "id": node.id,
                "type": "file",
                "file": node.path,
                "x": x,
                "y": y,
                "width": 360,
                "height": 120,
                "color": KIND_COLORS.get(node.kind, "0"),
            }
        else:
            canvas_node = {
                "id": node.id,
                "type": "text",
                "text": f"**{node.label}**\n\n_kind:_ `{node.kind}`",
                "x": x,
                "y": y,
                "width": 300,
                "height": 100,
                "color": KIND_COLORS.get(node.kind, "0"),
            }
        canvas_nodes.append(canvas_node)

    node_ids = {node.id for node in graph.nodes}
    canvas_edges = [
        {
            "id": f"edge-{idx}",
            "fromNode": edge.source,
            "toNode": edge.target,
            "label": edge.relation,
        }
        for idx, edge in enumerate(graph.edges)
        if edge.source in node_ids and edge.target in node_ids
    ]
    canvas = {"nodes": canvas_nodes, "edges": canvas_edges}
    path.write_text(json.dumps(canvas, indent=2) + "\n", encoding="utf-8")


def write_dashboard(graph: Graph, path: Path, canvas_name: str, json_name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for node in graph.nodes:
        counts[node.kind] = counts.get(node.kind, 0) + 1

    lines = [
        "---",
        "type: graph-dashboard",
        "area: security-research",
        "generated_by: vulnweave",
        "---",
        "",
        "# VulnWeave Graph",
        "",
        "Generated vulnerability research graph dashboard for security findings.",
        "",
        "## Open",
        "",
        f"- Canvas: [{canvas_name}](<{canvas_name}>)",
        f"- Graph JSON: [{json_name}](<{json_name}>)",
        "",
        "## Counts",
        "",
    ]
    for kind, count in sorted(counts.items()):
        lines.append(f"- {kind}: {count}")

    lines.extend(["", "## High-signal finding nodes", ""])
    for node in sorted(graph.nodes, key=lambda n: n.label):
        if node.kind == "finding":
            line = f"- [[{Path(node.path or node.name).stem}]]" if node.path else f"- {node.label}"
            lines.append(line)

    lines.extend(
        [
            "",
            "## Dataview helpers",
            "",
            "```dataview",
            "TABLE status, severity, cvss_score, cvss_confidence, target, pr",
            "FROM \"03 - Findings\"",
            "WHERE type = \"finding\"",
            "SORT file.mtime DESC",
            "```",
            "",
            "## Workflow use",
            "",
            "- Use the Canvas to spot duplicate/sibling variants before raising new PRs.",
            "- Use tag/CWE clusters to identify recurring bug-class playbooks.",
            "- Use repo/target edges to keep public PR, disclosure, and vault notes connected.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_vault_artifacts(graph: Graph, output_dir: Path) -> dict[str, Path]:
    graph_json = output_dir / "vulnweave-graph.json"
    canvas = output_dir / "VulnWeave Graph.canvas"
    dashboard = output_dir / "VulnWeave Graph.md"
    write_vault_graph_json(graph, graph_json)
    write_canvas(graph, canvas)
    write_dashboard(graph, dashboard, canvas_name=canvas.name, json_name=graph_json.name)
    return {"graph_json": graph_json, "canvas": canvas, "dashboard": dashboard}


def _layout(nodes: list[Node]) -> dict[str, tuple[int, int]]:
    by_kind: dict[str, list[Node]] = {}
    for node in nodes:
        by_kind.setdefault(node.kind, []).append(node)

    positions: dict[str, tuple[int, int]] = {}
    radius_step = 420
    kind_order = ["finding", "target", "repo", "pull_request", "cwe", "cve", "tag", "note"]
    for ring, kind in enumerate(kind_order):
        ring_nodes = by_kind.get(kind, [])
        if not ring_nodes:
            continue
        radius = max(1, ring + 1) * radius_step
        for index, node in enumerate(ring_nodes):
            angle = 2 * math.pi * index / max(len(ring_nodes), 1)
            positions[node.id] = (int(math.cos(angle) * radius), int(math.sin(angle) * radius))
    return positions
