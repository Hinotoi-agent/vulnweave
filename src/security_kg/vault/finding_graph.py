from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from security_kg.schema import Edge, Graph, Node
from security_kg.vault.obsidian import iter_markdown, parse_note


def build_vault_graph(
    vault: Path,
    findings_dir: str = "03 - Findings",
    targets_dir: str = "02 - Targets",
    include_all_notes: bool = False,
) -> Graph:
    include_dirs = None if include_all_notes else [findings_dir, targets_dir]
    notes = [parse_note(path, vault) for path in iter_markdown(vault, include_dirs)]
    title_to_id = {note.title: slug("note", note.title) for note in notes}

    graph = Graph(root=vault)
    for note in notes:
        note_id = title_to_id[note.title]
        graph.upsert_node(
            Node(
                id=note_id,
                kind=_node_kind(note.kind),
                name=note.title,
                file=note.rel_path,
                attrs={
                    "label": note.title,
                    "path": note.rel_path,
                    "status": note.frontmatter.get("status"),
                    "severity": note.frontmatter.get("severity"),
                },
            )
        )

    for note in notes:
        source_id = title_to_id[note.title]
        for link in sorted(note.wikilinks):
            target_id = title_to_id.get(link) or slug("note", link)
            graph.upsert_node(Node(id=target_id, kind="note", name=link, attrs={"label": link}))
            graph.add_unique_edge(Edge(source=source_id, target=target_id, kind="wikilinks"))

        for tag in sorted(note.tags):
            tag_id = slug("tag", tag)
            graph.upsert_node(Node(id=tag_id, kind="tag", name=tag, attrs={"label": f"#{tag}"}))
            graph.add_unique_edge(Edge(source=source_id, target=tag_id, kind="tagged"))

        for cwe in sorted(note.cwes):
            cwe_id = slug("cwe", cwe)
            graph.upsert_node(Node(id=cwe_id, kind="cwe", name=cwe, attrs={"label": cwe}))
            graph.add_unique_edge(Edge(source=source_id, target=cwe_id, kind="classified_as"))

        for cve in sorted(note.cves):
            cve_id = slug("cve", cve)
            graph.upsert_node(Node(id=cve_id, kind="cve", name=cve, attrs={"label": cve}))
            graph.add_unique_edge(Edge(source=source_id, target=cve_id, kind="assigned_cve"))

        for url in sorted(note.github_urls):
            if "/pull/" in url:
                continue
            repo_label = normalize_repo_url(url)
            repo_id = slug("repo", repo_label)
            graph.upsert_node(
                Node(
                    id=repo_id,
                    kind="repo",
                    name=repo_label,
                    attrs={"label": repo_label, "url": url},
                )
            )
            graph.add_unique_edge(Edge(source=source_id, target=repo_id, kind="references_repo"))

        for url in sorted(note.pr_urls):
            pr_label = short_pr_label(url)
            pr_id = slug("pr", url)
            graph.upsert_node(
                Node(
                    id=pr_id,
                    kind="pull_request",
                    name=pr_label,
                    attrs={"label": pr_label, "url": url},
                )
            )
            graph.add_unique_edge(Edge(source=source_id, target=pr_id, kind="raised_pr"))

    return graph


def slug(prefix: str, value: str) -> str:
    safe = value.strip().lower().replace(" ", "-")
    safe = "".join(ch if ch.isalnum() or ch in "-._/:#" else "-" for ch in safe)
    while "--" in safe:
        safe = safe.replace("--", "-")
    return f"{prefix}:{safe.strip('-')}"


def normalize_repo_url(url: str) -> str:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return url


def short_pr_label(url: str) -> str:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) >= 4 and parts[2] == "pull":
        return f"{parts[0]}/{parts[1]}#{parts[3]}"
    return url


def _node_kind(kind: str):
    if kind == "finding":
        return "finding"
    if kind == "target":
        return "target"
    return "note"
