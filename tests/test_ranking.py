from pathlib import Path

from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.ranking import build_review_bundle, rank_candidate_families


def test_ranks_candidates_by_family_for_first_pass_review(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        """
from app import CommandSpec

CommandSpec(name='/resume', handler='upload', remote_invocable=True)

def session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"

def load_session(session_id, backend):
    return backend.load_by_id(session_id)

def upload(filename, data, archive, llm, tool, backend, session_id):
    restored = backend.load_by_id(session_id)
    open(filename, 'wb').write(data)
    archive.extractall(filename)
    prompt = llm.chat(data)
    return tool.call_tool(prompt)
""".strip(),
        encoding="utf-8",
    )

    families = rank_candidate_families(find_candidates(map_repo(repo)))
    by_name = {family.family: family for family in families}

    assert "authz-object-ownership" in by_name
    assert "upload-path-containment" in by_name
    assert "plugin-mcp-agent-tool-boundary" in by_name
    assert by_name["upload-path-containment"].review_priority == "high"
    assert "app.py" in by_name["upload-path-containment"].top_paths
    assert by_name["upload-path-containment"].ranking_factors["sibling_density"] >= 1
    assert "duplicate/prior-art check" in by_name["upload-path-containment"].missing_proof


def test_builds_compact_review_bundle_with_source_snippets(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "gateway.py").write_text(
        """
from app import CommandSpec

CommandSpec(name='/resume', handler='resume_command', remote_invocable=True)

def session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"

def resume_command(backend, session_id):
    return backend.load_by_id(session_id)
""".strip(),
        encoding="utf-8",
    )

    bundle = build_review_bundle(
        map_repo(repo), top_families=1, snippets_per_family=4, max_lines_per_snippet=6
    )

    assert bundle["schema_version"] == "vulnweave.review_bundle.v1"
    assert bundle["family_count"] == 1
    family = bundle["families"][0]
    assert family["family"] == "authz-object-ownership"
    assert family["candidates"]
    assert family["snippets"]
    assert any("load_by_id" in snippet["text"] for snippet in family["snippets"])
    assert "Review only these ranked family bundles first" in bundle["budget_policy"]
