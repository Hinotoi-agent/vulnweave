from pathlib import Path

import pytest

from security_kg.cli import main
from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.io import write_graph_jsonl
from security_kg.vault.export import export_candidate_note


def test_export_candidate_to_obsidian_finding_note(tmp_path: Path):
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
    graph = map_repo(repo)
    candidate = find_candidates(graph)[0]
    vault = tmp_path / "vault"
    vault.mkdir()

    note = export_candidate_note(
        graph=graph,
        candidate_id=candidate.id,
        vault=vault,
        target="Target - Example App",
        repo_url="https://github.com/example-org/example-repo",
    )

    text = note.read_text(encoding="utf-8")
    assert note.name.startswith("Finding - Repo - Remote Resume")
    assert 'type: "finding"' in text
    assert 'target: "Target - Example App"' in text
    assert 'repo: "https://github.com/example-org/example-repo"' in text
    assert "## Duplicate check" in text
    assert "## Proof strategy" in text
    assert candidate.id in text


def test_cli_export_finding_from_graph_dir(tmp_path: Path, capsys):
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
    graph = map_repo(repo)
    graph_dir = tmp_path / "graph"
    write_graph_jsonl(graph, graph_dir)
    candidate = find_candidates(graph)[0]
    vault = tmp_path / "vault"
    vault.mkdir()

    assert (
        main(
            [
                "export-finding",
                str(graph_dir),
                "--candidate",
                candidate.id,
                "--vault",
                str(vault),
                "--target",
                "Target - Example App",
                "--repo-url",
                "https://github.com/example-org/example-repo",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out.strip()
    assert Path(out).exists()


def test_export_candidate_requires_existing_vault(tmp_path: Path):
    graph = _candidate_graph(tmp_path)
    candidate = find_candidates(graph)[0]
    missing_vault = tmp_path / "missing-vault"

    with pytest.raises(FileNotFoundError):
        export_candidate_note(
            graph=graph,
            candidate_id=candidate.id,
            vault=missing_vault,
            target="Target - Example App",
        )

    assert not missing_vault.exists()


def test_export_candidate_rejects_absolute_findings_dir(tmp_path: Path):
    graph = _candidate_graph(tmp_path)
    candidate = find_candidates(graph)[0]
    vault = tmp_path / "vault"
    vault.mkdir()

    with pytest.raises(ValueError, match="relative to the vault"):
        export_candidate_note(
            graph=graph,
            candidate_id=candidate.id,
            vault=vault,
            target="Target - Example App",
            findings_dir=str(tmp_path / "outside"),
        )


def test_export_candidate_rejects_findings_dir_traversal(tmp_path: Path):
    graph = _candidate_graph(tmp_path)
    candidate = find_candidates(graph)[0]
    vault = tmp_path / "vault"
    vault.mkdir()
    outside = tmp_path / "outside"

    with pytest.raises(ValueError, match="must not contain"):
        export_candidate_note(
            graph=graph,
            candidate_id=candidate.id,
            vault=vault,
            target="Target - Example App",
            findings_dir="../outside",
        )

    assert not outside.exists()


def test_export_candidate_allows_nested_findings_dir_under_vault(tmp_path: Path):
    graph = _candidate_graph(tmp_path)
    candidate = find_candidates(graph)[0]
    vault = tmp_path / "vault"
    vault.mkdir()

    note = export_candidate_note(
        graph=graph,
        candidate_id=candidate.id,
        vault=vault,
        target="Target - Example App",
        findings_dir="Findings/Security",
    )

    assert note.parent == vault / "Findings" / "Security"
    assert note.exists()


def _candidate_graph(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
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
    return map_repo(repo)
