from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.io import graph_to_dict, is_graph_dir, read_graph_jsonl, write_graph_jsonl
from security_kg.report import render_candidate_markdown
from security_kg.schema import Graph
from security_kg.vault.finding_graph import build_vault_graph
from security_kg.vault.writers import write_vault_artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="security-kg",
        description="Build security knowledge graphs from source repos and finding vaults.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    map_parser = subparsers.add_parser("map", help="Extract code graph nodes from a repository")
    map_parser.add_argument("repo", type=Path)
    map_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of a text summary",
    )
    map_parser.add_argument(
        "--out",
        type=Path,
        help="Write graph files to this directory as meta.json, nodes.jsonl, and edges.jsonl",
    )

    candidates_parser = subparsers.add_parser("candidates", help="Find invariant-backed candidates")
    candidates_parser.add_argument(
        "source",
        type=Path,
        help="Repository path or graph directory produced by `security-kg map --out`",
    )
    candidates_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of Markdown",
    )

    vault_graph_parser = subparsers.add_parser(
        "vault-graph",
        help="Build Obsidian-native graph artifacts from security finding notes",
    )
    vault_graph_parser.add_argument("--vault", required=True, type=Path, help="Path to vault")
    vault_graph_parser.add_argument("--findings-dir", default="03 - Findings")
    vault_graph_parser.add_argument("--targets-dir", default="02 - Targets")
    vault_graph_parser.add_argument("--output-dir", default="99 - Graph")
    vault_graph_parser.add_argument("--include-all-notes", action="store_true")
    vault_graph_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print summary JSON without writing Obsidian artifacts",
    )

    args = parser.parse_args(argv)

    if args.command == "map":
        graph = map_repo(args.repo)
        if args.out:
            write_graph_jsonl(graph, args.out)
        if args.json:
            print(json.dumps(graph_to_dict(graph), indent=2, sort_keys=True))
        else:
            suffix = f"; wrote JSONL graph to {args.out}" if args.out else ""
            print(
                f"Mapped {len(graph.nodes)} nodes and {len(graph.edges)} edges "
                f"from {graph.root}{suffix}"
            )
        return 0

    if args.command == "candidates":
        graph = _load_graph_or_map_repo(args.source)
        candidates = find_candidates(graph)
        if args.json:
            print(
                json.dumps(
                    [asdict(candidate) for candidate in candidates],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            if not candidates:
                print("No candidates found.")
            for candidate in candidates:
                print(render_candidate_markdown(candidate))
        return 0

    if args.command == "vault-graph":
        return _run_vault_graph(args)

    parser.error(f"unknown command: {args.command}")
    return 2


def _load_graph_or_map_repo(source: Path) -> Graph:
    if is_graph_dir(source):
        return read_graph_jsonl(source)
    return map_repo(source)


def _run_vault_graph(args: argparse.Namespace) -> int:
    vault = args.vault.expanduser().resolve()
    if not vault.exists() or not vault.is_dir():
        raise SystemExit(f"Vault does not exist or is not a directory: {vault}")

    graph = build_vault_graph(
        vault=vault,
        findings_dir=args.findings_dir,
        targets_dir=args.targets_dir,
        include_all_notes=args.include_all_notes,
    )
    output_dir = vault / args.output_dir
    outputs = {
        "graph_json": output_dir / "security-finding-graph.json",
        "canvas": output_dir / "Security Finding Graph.canvas",
        "dashboard": output_dir / "Security Finding Graph.md",
    }
    summary = {
        "vault": str(vault),
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "outputs": [str(path) for path in outputs.values()],
    }
    if not args.dry_run:
        write_vault_artifacts(graph, output_dir)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
