from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_kg.doctor import run_doctor
from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.io import (
    candidates_to_dict,
    graph_to_dict,
    is_graph_dir,
    read_graph_jsonl,
    write_graph_jsonl,
)
from security_kg.ranking import build_review_bundle, rank_candidate_families
from security_kg.report import render_candidate_markdown
from security_kg.schema import Graph
from security_kg.vault.export import export_candidate_note
from security_kg.vault.finding_graph import build_vault_graph
from security_kg.vault.insights import analyze_vault, render_insights
from security_kg.vault.writers import write_vault_artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vulnweave",
        description=(
            "Build local vulnerability research graphs from source repos and finding vaults."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    map_parser = subparsers.add_parser("map", help="Extract code graph nodes from a repository")
    map_parser.add_argument("repo", type=Path)
    map_parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of a text summary"
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
        help="Repository path or graph directory produced by `vulnweave map --out`",
    )
    candidates_parser.add_argument(
        "--json", action="store_true", help="Emit JSON instead of Markdown"
    )

    rank_parser = subparsers.add_parser(
        "rank",
        help="Group candidates by vulnerability family and rank them for review priority",
    )
    rank_parser.add_argument(
        "source",
        type=Path,
        help="Repository path or graph directory produced by `vulnweave map --out`",
    )
    rank_parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")

    bundle_parser = subparsers.add_parser(
        "bundle",
        help="Emit a compact ranked review bundle for low-token LLM or manual review",
    )
    bundle_parser.add_argument(
        "source",
        type=Path,
        help="Repository path or graph directory produced by `vulnweave map --out`",
    )
    bundle_parser.add_argument("--top-families", type=int, default=5)
    bundle_parser.add_argument("--snippets-per-family", type=int, default=10)
    bundle_parser.add_argument("--max-lines-per-snippet", type=int, default=12)
    bundle_parser.add_argument("--out", type=Path, help="Write bundle JSON to this path")

    export_parser = subparsers.add_parser(
        "export-finding",
        help="Export a candidate from a graph directory into an Obsidian finding note",
    )
    export_parser.add_argument("source", type=Path, help="Repository path or graph directory")
    export_parser.add_argument("--candidate", required=True, help="Candidate ID to export")
    export_parser.add_argument("--vault", required=True, type=Path, help="Path to Obsidian vault")
    export_parser.add_argument(
        "--target", required=True, help="Target note title, e.g. Target - App"
    )
    export_parser.add_argument("--repo-url", help="Public repository URL to store in frontmatter")
    export_parser.add_argument("--status", default="draft")
    export_parser.add_argument("--findings-dir", default="03 - Findings")
    export_parser.add_argument("--overwrite", action="store_true")

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

    insights_parser = subparsers.add_parser(
        "vault-insights",
        help="Print duplicate, draft, missing-field, and variant insights for a vault",
    )
    insights_parser.add_argument("--vault", required=True, type=Path)
    insights_parser.add_argument("--findings-dir", default="03 - Findings")
    insights_parser.add_argument("--targets-dir", default="02 - Targets")
    insights_parser.add_argument("--json", action="store_true")

    doctor_parser = subparsers.add_parser("doctor", help="Check local VulnWeave inputs and paths")
    doctor_parser.add_argument("--repo", type=Path)
    doctor_parser.add_argument("--graph", type=Path)
    doctor_parser.add_argument("--vault", type=Path)

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
            print(json.dumps(candidates_to_dict(candidates, args.source), indent=2, sort_keys=True))
        else:
            if not candidates:
                print("No candidates found.")
            for candidate in candidates:
                print(render_candidate_markdown(candidate))
        return 0

    if args.command == "rank":
        graph = _load_graph_or_map_repo(args.source)
        families = rank_candidate_families(find_candidates(graph))
        if args.json:
            print(json.dumps({"families": [family.__dict__ for family in families]}, indent=2, sort_keys=True))
        else:
            if not families:
                print("No candidate families found.")
            for family in families:
                print(
                    f"{family.review_priority.upper()} {family.family}: "
                    f"score={family.score}, candidates={family.candidate_count}, "
                    f"duplicate_risk={family.duplicate_risk}"
                )
                print(f"  invariant: {family.shared_invariant}")
                if family.top_paths:
                    print(f"  top paths: {', '.join(family.top_paths[:5])}")
        return 0

    if args.command == "bundle":
        graph = _load_graph_or_map_repo(args.source)
        bundle = build_review_bundle(
            graph,
            top_families=args.top_families,
            snippets_per_family=args.snippets_per_family,
            max_lines_per_snippet=args.max_lines_per_snippet,
        )
        output = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(output, encoding="utf-8")
            print(str(args.out))
        else:
            print(output, end="")
        return 0

    if args.command == "export-finding":
        graph = _load_graph_or_map_repo(args.source)
        note_path = export_candidate_note(
            graph=graph,
            candidate_id=args.candidate,
            vault=args.vault,
            target=args.target,
            repo_url=args.repo_url,
            status=args.status,
            findings_dir=args.findings_dir,
            overwrite=args.overwrite,
        )
        print(str(note_path))
        return 0

    if args.command == "vault-graph":
        return _run_vault_graph(args)

    if args.command == "vault-insights":
        insights = analyze_vault(
            vault=args.vault,
            findings_dir=args.findings_dir,
            targets_dir=args.targets_dir,
        )
        if args.json:
            print(json.dumps(insights.__dict__, indent=2, sort_keys=True))
        else:
            print(render_insights(insights))
        return 0

    if args.command == "doctor":
        code, lines = run_doctor(repo=args.repo, graph=args.graph, vault=args.vault)
        print("\n".join(lines))
        return code

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
        "graph_json": output_dir / "vulnweave-graph.json",
        "canvas": output_dir / "VulnWeave Graph.canvas",
        "dashboard": output_dir / "VulnWeave Graph.md",
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
