from pathlib import Path

from security_kg.extract import map_repo
from security_kg.invariants import find_candidates
from security_kg.io import read_graph_jsonl, write_graph_jsonl
from security_kg.report import render_candidate_markdown


def test_maps_command_registry_and_session_scope(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source = repo / "registry.py"
    source.write_text(
        """
from app import CommandSpec

COMMANDS = [
    CommandSpec(
        name='/resume',
        handler='resume_command',
        remote_invocable=True,
        remote_admin_opt_in=False,
    )
]

def build_session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"

def resume_command(backend, session_id):
    return backend.load_by_id(session_id)
""".strip(),
        encoding="utf-8",
    )

    graph = map_repo(repo)

    commands = [node for node in graph.nodes if node.kind == "command"]
    assert len(commands) == 1
    assert commands[0].name == "/resume"
    assert commands[0].attrs["remote_invocable"] is True
    assert commands[0].attrs["remote_admin_opt_in"] is False

    assert any(
        node.kind == "session_scope" and "sender" in node.attrs["parts"] for node in graph.nodes
    )
    assert any(node.kind == "sink" and node.name == "load_by_id" for node in graph.nodes)
    assert any(edge.kind == "handled_by" for edge in graph.edges)
    assert any(edge.kind == "calls" for edge in graph.edges)


def test_flags_remote_resume_direct_load_drift(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_vulnerable_fixture(repo)

    graph = map_repo(repo)
    candidates = find_candidates(graph)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.pattern == "remote-command-session-direct-load"
    assert candidate.severity_hint == "high"
    assert "/resume" in candidate.title
    assert "remote chat sender" in candidate.boundary
    assert "load_by_id" in "\n".join(candidate.evidence)
    assert any("handler resume_command" in step for step in candidate.graph_path)

    markdown = render_candidate_markdown(candidate)
    assert "## Candidate" in markdown
    assert "Violated invariant" in markdown
    assert "Proof strategy" in markdown
    assert "Seed one actor" in markdown


def test_remote_command_direct_load_uses_handler_local_sink(tmp_path: Path):
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

def unrelated_debug(backend, session_id):
    return backend.get_by_id(session_id)
""".strip(),
        encoding="utf-8",
    )

    candidates = find_candidates(map_repo(repo))
    remote = [
        candidate
        for candidate in candidates
        if candidate.pattern == "remote-command-session-direct-load"
    ]

    assert len(remote) == 1
    assert remote[0].id == "resume-load_by_id-3"
    assert "load_by_id" in "\n".join(remote[0].evidence)


def test_remote_command_direct_load_ignores_unrelated_repo_wide_sink(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "gateway.py").write_text(
        """
from app import CommandSpec

CommandSpec(name='/resume', handler='resume_command', remote_invocable=True)

def session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"

def resume_command(backend, session_id):
    return backend.safe_resume(session_id)
""".strip(),
        encoding="utf-8",
    )
    (repo / "storage.py").write_text(
        """
def unrelated_admin_restore(backend, session_id):
    return backend.load_by_id(session_id)
""".strip(),
        encoding="utf-8",
    )

    patterns = {candidate.pattern for candidate in find_candidates(map_repo(repo))}

    assert "remote-command-session-direct-load" not in patterns


def test_remote_command_without_handler_falls_back_to_same_file_sink(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "gateway.py").write_text(
        """
from app import CommandSpec

CommandSpec(name='/resume', remote_invocable=True)

def session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"

def local_resume(backend, session_id):
    return backend.read_by_id(session_id)
""".strip(),
        encoding="utf-8",
    )

    patterns = {candidate.pattern for candidate in find_candidates(map_repo(repo))}

    assert "remote-command-session-direct-load" in patterns


def test_round_trips_graph_jsonl_and_finds_candidates(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    write_vulnerable_fixture(repo)

    graph_dir = tmp_path / "graph"
    original = map_repo(repo)
    write_graph_jsonl(original, graph_dir)
    loaded = read_graph_jsonl(graph_dir)

    assert loaded.root == original.root
    assert [node.id for node in loaded.nodes] == [node.id for node in original.nodes]
    assert [edge.target for edge in loaded.edges] == [edge.target for edge in original.edges]
    assert find_candidates(loaded)[0].pattern == "remote-command-session-direct-load"


def test_detects_additional_high_signal_patterns(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        """
from app import CommandSpec

CommandSpec(name='/upload', handler='upload', remote_invocable=True)

def scoped_query(user, tenant, db):
    return db.query('items').filter(user=user, tenant=tenant)

def get_item(item_id, db):
    return db.get_by_id(item_id)

def upload(filename, data, archive, llm, tool):
    open(filename, 'wb').write(data)
    archive.extractall(filename)
    prompt = llm.chat(data)
    return tool.call_tool(prompt)

@app.route('/webhook')
def webhook(path):
    return open(path, 'w')
""".strip(),
        encoding="utf-8",
    )

    patterns = {candidate.pattern for candidate in find_candidates(map_repo(repo))}

    assert "list-filter-direct-load-drift" in patterns
    assert "upload-write-path-traversal-or-symlink-risk" in patterns
    assert "prompt-content-injection-to-host-tool-boundary" in patterns
    assert "public-webhook-route-auth-drift" in patterns


def test_detects_bearer_handle_without_scope(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        """
from app import CommandSpec

CommandSpec(name='/artifact', handler='get_artifact', remote_invocable=True)

def get_artifact(artifact_id, db):
    return db.get_by_id(artifact_id)
""".strip(),
        encoding="utf-8",
    )

    patterns = {candidate.pattern for candidate in find_candidates(map_repo(repo))}
    assert "bearer-handle-ownership-gap" in patterns


def write_vulnerable_fixture(repo: Path) -> None:
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
