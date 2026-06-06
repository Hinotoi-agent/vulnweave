from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from security_kg.invariants import find_candidates
from security_kg.schema import Candidate, Graph, Node

FAMILY_BY_PATTERN = {
    "remote-command-session-direct-load": "authz-object-ownership",
    "list-filter-direct-load-drift": "authz-object-ownership",
    "bearer-handle-ownership-gap": "authz-object-ownership",
    "upload-write-path-traversal-or-symlink-risk": "upload-path-containment",
    "prompt-content-injection-to-host-tool-boundary": "plugin-mcp-agent-tool-boundary",
    "public-webhook-route-auth-drift": "authz-public-route-privileged-action",
    "provider-endpoint-override-secret-exfiltration": "ssrf-provider-endpoint-secret-exfil",
}

FAMILY_RANKING_DEFAULTS = {
    "authz-object-ownership": {
        "reachability": 4,
        "boundary_crossing": 5,
        "exploit_impact": 4,
        "novelty": 4,
        "maintainer_value": 5,
        "duplicate_risk": 2,
        "shared_invariant": (
            "caller-controlled object/session handles must be re-scoped before direct "
            "load/read/update/delete operations"
        ),
    },
    "upload-path-containment": {
        "reachability": 4,
        "boundary_crossing": 5,
        "exploit_impact": 5,
        "novelty": 3,
        "maintainer_value": 5,
        "duplicate_risk": 3,
        "shared_invariant": (
            "untrusted filenames, paths, and archive members must be canonicalized "
            "and contained before filesystem writes"
        ),
    },
    "plugin-mcp-agent-tool-boundary": {
        "reachability": 3,
        "boundary_crossing": 5,
        "exploit_impact": 5,
        "novelty": 5,
        "maintainer_value": 4,
        "duplicate_risk": 2,
        "shared_invariant": (
            "untrusted prompt/content must not silently cross into host-side tools "
            "or privileged agent capabilities"
        ),
    },
    "authz-public-route-privileged-action": {
        "reachability": 5,
        "boundary_crossing": 4,
        "exploit_impact": 4,
        "novelty": 3,
        "maintainer_value": 4,
        "duplicate_risk": 3,
        "shared_invariant": (
            "public routes and webhooks must authenticate or verify requests before "
            "privileged side effects"
        ),
    },
    "ssrf-provider-endpoint-secret-exfil": {
        "reachability": 3,
        "boundary_crossing": 5,
        "exploit_impact": 5,
        "novelty": 5,
        "maintainer_value": 5,
        "duplicate_risk": 2,
        "shared_invariant": (
            "provider endpoint overrides must be validated before credential discovery "
            "and credentialed request construction"
        ),
    },
}


@dataclass(frozen=True)
class FamilySummary:
    family: str
    candidate_count: int
    review_priority: str
    score: int
    shared_invariant: str
    top_patterns: list[str]
    top_paths: list[str]
    representative_candidates: list[str]
    ranking_factors: dict[str, int]
    token_budget_hint: str
    duplicate_risk: str
    novelty_hint: str
    missing_proof: list[str] = field(default_factory=list)


def rank_candidate_families(candidates: list[Candidate]) -> list[FamilySummary]:
    grouped: dict[str, list[Candidate]] = {}
    for candidate in candidates:
        grouped.setdefault(family_for_candidate(candidate), []).append(candidate)

    summaries = [_summarize_family(family, items) for family, items in grouped.items()]
    return sorted(summaries, key=lambda item: (-item.score, item.family))


def build_review_bundle(
    graph: Graph,
    *,
    top_families: int = 5,
    snippets_per_family: int = 10,
    max_lines_per_snippet: int = 12,
    novelty_signals: int = 3,
) -> dict[str, Any]:
    candidates = find_candidates(graph)
    families = rank_candidate_families(candidates)[:top_families]
    by_id = {candidate.id: candidate for candidate in candidates}
    known_family_names = [family.family for family in families]
    return {
        "schema_version": "vulnweave.review_bundle.v2",
        "source": str(graph.root),
        "budget_policy": (
            "Use deterministic ranked family bundles for the main review, but reserve a "
            "small novelty lane for weird cross-component signals. Do not ask an LLM to "
            "rediscover from the whole repo; ask it to validate one anchored bundle or "
            "produce candidate contracts from the novelty lane."
        ),
        "review_lanes": {
            "known_family_validation": "70%",
            "vault_variant_hunt": "20%",
            "novelty_hunt": "10%",
        },
        "family_count": len(families),
        "candidate_count": len(candidates),
        "families": [
            _family_bundle(
                graph.root,
                family,
                by_id,
                snippets_per_family=snippets_per_family,
                max_lines_per_snippet=max_lines_per_snippet,
            )
            for family in families
        ],
        "novelty_lane": _build_novelty_lane(
            graph,
            known_family_names=known_family_names,
            max_signals=novelty_signals,
            max_lines_per_snippet=max_lines_per_snippet,
        ),
    }


def family_for_candidate(candidate: Candidate) -> str:
    return FAMILY_BY_PATTERN.get(candidate.pattern, candidate.pattern)


def _summarize_family(family: str, candidates: list[Candidate]) -> FamilySummary:
    factors = _ranking_factors(family, candidates)
    score = sum(factors.values()) - factors["duplicate_risk"]
    paths = _top_paths(candidates)
    patterns = sorted({candidate.pattern for candidate in candidates})
    return FamilySummary(
        family=family,
        candidate_count=len(candidates),
        review_priority=_priority(score),
        score=score,
        shared_invariant=str(
            FAMILY_RANKING_DEFAULTS.get(family, {}).get(
                "shared_invariant", "review the shared invariant across this candidate family"
            )
        ),
        top_patterns=patterns[:5],
        top_paths=paths[:8],
        representative_candidates=[candidate.id for candidate in candidates[:5]],
        ranking_factors=factors,
        token_budget_hint=_token_budget_hint(len(candidates), len(paths)),
        duplicate_risk=_risk_label(factors["duplicate_risk"]),
        novelty_hint=_novelty_hint(factors["novelty"]),
        missing_proof=_missing_proof_for_family(family),
    )


def _ranking_factors(family: str, candidates: list[Candidate]) -> dict[str, int]:
    defaults = FAMILY_RANKING_DEFAULTS.get(family, {})
    factors = {
        "reachability": int(defaults.get("reachability", 3)),
        "boundary_crossing": int(defaults.get("boundary_crossing", 3)),
        "exploit_impact": int(defaults.get("exploit_impact", 3)),
        "novelty": int(defaults.get("novelty", 3)),
        "sibling_density": min(5, max(1, len(candidates))),
        "maintainer_value": int(defaults.get("maintainer_value", 3)),
        "duplicate_risk": int(defaults.get("duplicate_risk", 3)),
    }
    if any(candidate.severity_hint == "high" for candidate in candidates):
        factors["exploit_impact"] = min(5, factors["exploit_impact"] + 1)
    return factors


def _family_bundle(
    repo_root: Path,
    family: FamilySummary,
    by_id: dict[str, Candidate],
    *,
    snippets_per_family: int,
    max_lines_per_snippet: int,
) -> dict[str, Any]:
    candidates = [by_id[candidate_id] for candidate_id in family.representative_candidates]
    snippets = []
    seen_locations: set[str] = set()
    for candidate in candidates:
        for location in _candidate_locations(candidate):
            if location in seen_locations:
                continue
            seen_locations.add(location)
            snippet = _read_snippet(repo_root, location, max_lines_per_snippet)
            if snippet:
                snippets.append(snippet)
            if len(snippets) >= snippets_per_family:
                break
        if len(snippets) >= snippets_per_family:
            break
    return {
        **family.__dict__,
        "candidates": [candidate.__dict__ for candidate in candidates],
        "snippets": snippets,
    }


def _candidate_locations(candidate: Candidate) -> list[str]:
    locations: list[str] = []
    for text in [*candidate.evidence, *candidate.graph_path]:
        for token in text.replace("(", " ").replace(")", " ").split():
            if ":" not in token:
                continue
            file_part, line_part = token.rsplit(":", 1)
            if line_part.rstrip(",").isdigit() and file_part:
                locations.append(f"{file_part}:{line_part.rstrip(',')}")
    return locations


def _read_snippet(repo_root: Path, location: str, max_lines: int) -> dict[str, Any] | None:
    file_name, line_text = location.rsplit(":", 1)
    line = int(line_text)
    path = repo_root / file_name
    if not path.exists() or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    start = max(1, line - max_lines // 2)
    end = min(len(lines), start + max_lines - 1)
    return {
        "file": file_name,
        "line": line,
        "start_line": start,
        "end_line": end,
        "text": "\n".join(f"{number}|{lines[number - 1]}" for number in range(start, end + 1)),
    }


def _build_novelty_lane(
    graph: Graph,
    *,
    known_family_names: list[str],
    max_signals: int,
    max_lines_per_snippet: int,
) -> dict[str, Any]:
    signals = _rank_novelty_signals(graph)[:max_signals]
    return {
        "purpose": (
            "Preserve the chance of unique findings outside the built-in bug families by "
            "showing compact, anchored weirdness signals to an LLM or human reviewer."
        ),
        "review_rule": (
            "Spend a bounded pass here after known-family triage. Each signal must become a "
            "candidate contract with boundary, source, sink, invariant, proof plan, and "
            "duplicate-check terms before deeper validation."
        ),
        "excluded_known_families": known_family_names,
        "signals": [
            {
                **signal,
                "snippets": [
                    snippet
                    for location in signal["locations"]
                    if (snippet := _read_snippet(graph.root, location, max_lines_per_snippet))
                    is not None
                ][:2],
            }
            for signal in signals
        ],
        "candidate_contract_prompt": (
            "For each novelty signal, do not assert a bug from pattern name alone. Decide if "
            "there is a trust-boundary crossing not already covered by excluded_known_families; "
            "then emit a compact contract: title, affected boundary, untrusted source, privileged "
            "sink, violated invariant, duplicate-search terms, and the cheapest safe proof."
        ),
    }


def _rank_novelty_signals(graph: Graph) -> list[dict[str, Any]]:
    by_scope: dict[str, list[Node]] = {}
    for node in graph.nodes:
        scope = _novelty_scope(node)
        if not scope:
            continue
        by_scope.setdefault(scope, []).append(node)

    signals: list[dict[str, Any]] = []
    for scope, nodes in by_scope.items():
        kinds = {node.kind for node in nodes}
        capabilities = {
            str(node.attrs.get("capability"))
            for node in nodes
            if node.kind == "sink" and node.attrs.get("capability")
        }
        categories = {
            category
            for node in nodes
            if node.kind == "validation_guard"
            for category in node.attrs.get("categories", [])
        }
        score = 0
        reasons: list[str] = []
        if {"request_sink", "credential_source"} <= kinds:
            score += 5
            reasons.append("credential material and outbound request construction share a scope")
        if {"request_sink", "validation_guard"} <= kinds:
            score += 3
            reasons.append(
                "network guard and request sink share a scope; review redirect/DNS/header drift"
            )
        if {"provider_endpoint_control", "credential_source"} <= kinds:
            score += 4
            reasons.append("provider endpoint override appears near credential discovery")
        if "llm_prompt" in capabilities and (
            capabilities & {"host_tool", "filesystem_write", "shell_execution"}
        ):
            score += 5
            reasons.append("model/prompt path shares a scope with host-side capabilities")
        if {"route", "webhook"} & kinds and (
            capabilities
            & {"filesystem_write", "shell_execution", "host_tool", "direct_object_load"}
        ):
            score += 4
            reasons.append("remote HTTP entry shares a scope with privileged local capability")
        if "path" in categories and "filesystem_write" in capabilities:
            score += 3
            reasons.append(
                "path validation and filesystem write share a scope; review guard/write coupling"
            )
        if score <= 0:
            continue
        locations = sorted(
            {
                f"{node.file}:{node.line}"
                for node in nodes
                if node.file and node.line
            }
        )
        signals.append(
            {
                "scope": scope,
                "score": score,
                "reasons": reasons,
                "node_kinds": sorted(kinds),
                "capabilities": sorted(capability for capability in capabilities if capability),
                "locations": locations[:6],
            }
        )
    return sorted(signals, key=lambda item: (-item["score"], item["scope"]))


def _novelty_scope(node: Node) -> str | None:
    function_name = node.attrs.get("enclosing_function") or node.attrs.get("handler")
    if isinstance(function_name, str) and function_name:
        return f"{node.file}::{function_name}"
    if node.file:
        return node.file
    return None


def _top_paths(candidates: list[Candidate]) -> list[str]:
    counts: dict[str, int] = {}
    for candidate in candidates:
        for location in _candidate_locations(candidate):
            file_name = location.rsplit(":", 1)[0]
            counts[file_name] = counts.get(file_name, 0) + 1
    return [path for path, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def _priority(score: int) -> str:
    if score >= 23:
        return "high"
    if score >= 18:
        return "medium"
    return "low"


def _risk_label(value: int) -> str:
    if value >= 4:
        return "high"
    if value == 3:
        return "medium"
    return "low"


def _novelty_hint(value: int) -> str:
    if value >= 5:
        return "likely under-covered class; still run vault/GitHub duplicate checks"
    if value >= 3:
        return "possible variant; compare against vault notes and public prior art"
    return "common class; require a specific novel angle before deep review"


def _token_budget_hint(candidate_count: int, path_count: int) -> str:
    if candidate_count <= 2 and path_count <= 3:
        return "cheap-model review or manual inspection should be enough before proof work"
    return "bundle snippets first; send only representative paths to expensive model review"


def _missing_proof_for_family(family: str) -> list[str]:
    common = [
        "attacker/control boundary",
        "complete source-to-sink reachability",
        "duplicate/prior-art check",
        "minimal safe repro or negative regression",
    ]
    family_specific = {
        "upload-path-containment": [
            "final path containment after canonicalization",
            "symlink/archive member behavior",
        ],
        "authz-object-ownership": [
            "cross-user or cross-tenant object ownership check",
            "sensitive asset impact",
        ],
        "plugin-mcp-agent-tool-boundary": [
            "host capability reached without approval/sandbox",
            "prompt/content treated as instructions",
        ],
        "ssrf-provider-endpoint-secret-exfil": [
            "credential lookup before endpoint validation",
            "redirect/header forwarding behavior",
        ],
        "authz-public-route-privileged-action": [
            "unauthenticated route reachability",
            "privileged side effect before auth/signature verification",
        ],
    }
    return [*common, *family_specific.get(family, [])]
