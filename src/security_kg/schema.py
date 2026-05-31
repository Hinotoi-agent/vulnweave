from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

NodeKind = Literal[
    "command",
    "function",
    "sink",
    "session_scope",
    "route",
    "webhook",
    "file",
    "finding",
    "target",
    "repo",
    "pull_request",
    "cwe",
    "cve",
    "tag",
    "note",
    "provider_endpoint_control",
    "credential_source",
    "request_sink",
    "validation_guard",
]
EdgeKind = Literal[
    "defined_in",
    "calls",
    "handled_by",
    "uses_scope",
    "evidence",
    "wikilinks",
    "tagged",
    "classified_as",
    "assigned_cve",
    "references_repo",
    "raised_pr",
    "uses_endpoint",
    "resolves_credential",
    "sends_request",
    "guarded_by",
]


@dataclass(frozen=True)
class Node:
    id: str
    kind: NodeKind
    name: str
    file: str = ""
    line: int = 0
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return str(self.attrs.get("label") or self.name)

    @property
    def path(self) -> str | None:
        path = self.attrs.get("path") or self.file
        return str(path) if path else None


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: EdgeKind
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def relation(self) -> str:
        return self.kind.replace("_", "-")


@dataclass
class Graph:
    root: Path
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def upsert_node(self, node: Node) -> None:
        for index, existing in enumerate(self.nodes):
            if existing.id == node.id:
                merged_attrs = {**existing.attrs, **node.attrs}
                self.nodes[index] = Node(
                    id=existing.id,
                    kind=existing.kind,
                    name=existing.name,
                    file=existing.file or node.file,
                    line=existing.line or node.line,
                    attrs=merged_attrs,
                )
                return
        self.nodes.append(node)

    def add_unique_edge(self, edge: Edge) -> None:
        if edge not in self.edges:
            self.edges.append(edge)

    def node_by_id(self, node_id: str) -> Node | None:
        return next((node for node in self.nodes if node.id == node_id), None)


@dataclass(frozen=True)
class Candidate:
    id: str
    title: str
    pattern: str
    severity_hint: str
    boundary: str
    violated_invariant: str
    graph_path: list[str]
    evidence: list[str]
    proof_strategy: list[str]
