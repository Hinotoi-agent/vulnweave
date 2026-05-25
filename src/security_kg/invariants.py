from __future__ import annotations

from security_kg.schema import Candidate, Graph, Node

CONTROL_PLANE_COMMAND_NAMES = {"/resume", "/summary", "/debug", "/config", "/shell", "/tools"}
DIRECT_LOAD_SINKS = {"load_by_id", "get_by_id", "read_by_id"}
PRIVILEGED_CAPABILITIES = {"direct_object_load", "filesystem_write", "shell_execution", "host_tool"}


def find_candidates(graph: Graph) -> list[Candidate]:
    candidates: list[Candidate] = []
    commands = [node for node in graph.nodes if node.kind == "command"]
    routes = [node for node in graph.nodes if node.kind in {"route", "webhook"}]
    sinks = [node for node in graph.nodes if node.kind == "sink"]
    scopes = [node for node in graph.nodes if node.kind == "session_scope"]

    candidates.extend(_remote_command_direct_load(graph, commands, sinks, scopes))
    candidates.extend(_list_filter_direct_load_drift(sinks, scopes))
    candidates.extend(_bearer_handle_ownership_gap(sinks, commands, routes, scopes))
    candidates.extend(_upload_write_path_risk(sinks, commands, routes))
    candidates.extend(_prompt_tool_boundary_risk(sinks, commands, routes))
    candidates.extend(_public_route_privileged_action(routes, sinks))
    return _dedupe(candidates)


def _remote_command_direct_load(
    graph: Graph,
    commands: list[Node],
    sinks: list[Node],
    scopes: list[Node],
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for command in commands:
        if not _is_remote_control_plane_command(command):
            continue
        sink = _direct_load_sink_for_command(graph, command)
        scope = _scope_for_command(graph, command)
        if sink is None or scope is None:
            continue
        handler = _handler_for(graph, command)
        graph_path = [
            "remote chat sender",
            f"command {command.name} ({command.file}:{command.line})",
        ]
        if handler:
            graph_path.append(f"handler {handler.name} ({handler.file}:{handler.line})")
        graph_path.append(f"sink {sink.name} ({sink.file}:{sink.line})")
        candidates.append(
            Candidate(
                id=_candidate_id(command, sink),
                title=f"Remote {command.name} can reach direct session/object load",
                pattern="remote-command-session-direct-load",
                severity_hint="high",
                boundary="remote chat sender -> command dispatcher -> session/object restore",
                violated_invariant=(
                    "Remote session-scoped actors must not invoke global restore/list/read "
                    "operations without re-authorizing the same sender/session scope."
                ),
                graph_path=graph_path,
                evidence=[
                    f"{command.file}:{command.line} registers {command.name} with "
                    f"remote_invocable={command.attrs.get('remote_invocable')!r}",
                    f"{scope.file}:{scope.line} builds scoped session key parts "
                    f"{', '.join(scope.attrs['parts'])}",
                    (
                        f"{sink.file}:{sink.line} calls {sink.name}, "
                        "a direct object/session load sink"
                    ),
                ],
                proof_strategy=[
                    "Seed one actor's session/object with a unique marker.",
                    f"Invoke {command.name} as a different remote actor.",
                    "Assert the first actor's ID/marker is not listed, loaded, or summarized.",
                    "Assert the direct load sink is not reached for the wrong actor scope.",
                ],
            )
        )
    return candidates


def _list_filter_direct_load_drift(sinks: list[Node], scopes: list[Node]) -> list[Candidate]:
    query = next((node for node in sinks if node.attrs.get("capability") == "scoped_query"), None)
    direct = next((node for node in sinks if node.name in DIRECT_LOAD_SINKS), None)
    if not query or not direct or not scopes:
        return []
    return [
        Candidate(
            id=f"list-filter-direct-load-{direct.line}",
            title="Scoped list/query path coexists with global direct-load path",
            pattern="list-filter-direct-load-drift",
            severity_hint="medium",
            boundary="scoped list/query actor -> direct object load by caller-supplied id",
            violated_invariant=(
                "Any direct object load reachable from an untrusted actor should enforce the same "
                "user/tenant/owner scope as the corresponding list or query path."
            ),
            graph_path=[
                f"scoped query {query.name} ({query.file}:{query.line})",
                f"scope hint {scopes[0].name} ({scopes[0].file}:{scopes[0].line})",
                f"direct load {direct.name} ({direct.file}:{direct.line})",
            ],
            evidence=[
                f"{query.file}:{query.line} contains a scoped query/list-like call {query.name}",
                f"{direct.file}:{direct.line} contains direct object load {direct.name}",
                (
                    f"{scopes[0].file}:{scopes[0].line} suggests actor scope parts "
                    f"{', '.join(scopes[0].attrs['parts'])}"
                ),
            ],
            proof_strategy=[
                "Create two actors with different objects/resources.",
                "Verify the list/query path only returns the current actor's resources.",
                "Call the direct-load path with the other actor's object ID.",
                "Confirm the same actor/tenant predicate is enforced before returning data.",
            ],
        )
    ]


def _bearer_handle_ownership_gap(
    sinks: list[Node], commands: list[Node], routes: list[Node], scopes: list[Node]
) -> list[Candidate]:
    direct = next((node for node in sinks if node.name in DIRECT_LOAD_SINKS), None)
    if not direct or scopes:
        return []
    if not (commands or routes or direct.attrs.get("uses_untrusted_param")):
        return []
    entry = (commands or routes or [direct])[0]
    return [
        Candidate(
            id=f"bearer-handle-ownership-{direct.line}",
            title=(
                "Caller-supplied handle reaches direct resource load without visible scope evidence"
            ),
            pattern="bearer-handle-ownership-gap",
            severity_hint="high",
            boundary=(
                "untrusted actor supplies opaque resource id -> object/session/job/artifact load"
            ),
            violated_invariant=(
                "Opaque IDs such as session, job, artifact, conversation, and file handles "
                "are bearer "
                "capabilities unless each load re-checks ownership or tenant scope."
            ),
            graph_path=[
                f"entry {entry.name} ({entry.file}:{entry.line})",
                f"direct load {direct.name} ({direct.file}:{direct.line})",
            ],
            evidence=[
                (
                    f"{direct.file}:{direct.line} calls {direct.name} with arguments "
                    f"{direct.attrs.get('args')}"
                ),
                "No session/user/tenant scope construction was detected in the mapped repository.",
            ],
            proof_strategy=[
                "Create two actors and capture an opaque resource ID from actor A.",
                "Use actor B to request/load the captured ID through the mapped entry point.",
                "Assert actor B cannot observe, mutate, resume, or download actor A's resource.",
            ],
        )
    ]


def _upload_write_path_risk(
    sinks: list[Node], commands: list[Node], routes: list[Node]
) -> list[Candidate]:
    fs = next((node for node in sinks if node.attrs.get("capability") == "filesystem_write"), None)
    if not fs:
        return []
    entry = (routes or commands or [fs])[0]
    return [
        Candidate(
            id=f"upload-write-path-{fs.line}",
            title="Untrusted path or archive data may reach filesystem write/extract sink",
            pattern="upload-write-path-traversal-or-symlink-risk",
            severity_hint="high",
            boundary="uploaded filename/archive member/path parameter -> host filesystem write",
            violated_invariant=(
                "Untrusted filenames, paths, and archive members must be canonicalized, "
                "constrained "
                "to an intended base directory, and protected from symlink/clobber writes."
            ),
            graph_path=[
                f"entry {entry.name} ({entry.file}:{entry.line})",
                f"filesystem sink {fs.name} ({fs.file}:{fs.line})",
            ],
            evidence=[
                (
                    f"{fs.file}:{fs.line} calls filesystem sink {fs.name} with arguments "
                    f"{fs.attrs.get('args')}"
                ),
            ],
            proof_strategy=[
                (
                    "Try traversal names such as ../outside.txt and nested absolute paths "
                    "in a temp root."
                ),
                (
                    "If archives are accepted, include traversal and symlink members in a "
                    "safe fixture."
                ),
                (
                    "Assert writes stay under the expected base directory and do not clobber "
                    "existing files."
                ),
            ],
        )
    ]


def _prompt_tool_boundary_risk(
    sinks: list[Node], commands: list[Node], routes: list[Node]
) -> list[Candidate]:
    prompt = next((node for node in sinks if node.attrs.get("capability") == "llm_prompt"), None)
    tool = next(
        (
            node
            for node in sinks
            if node.attrs.get("capability") in {"host_tool", "shell_execution", "filesystem_write"}
        ),
        None,
    )
    if not prompt or not tool:
        return []
    entry = (commands or routes or [prompt])[0]
    return [
        Candidate(
            id=f"prompt-tool-boundary-{prompt.line}-{tool.line}",
            title="Untrusted prompt/content path coexists with host-side tool capability",
            pattern="prompt-content-injection-to-host-tool-boundary",
            severity_hint="high",
            boundary="untrusted document/message/web content -> model context -> host-side tool",
            violated_invariant=(
                "Untrusted content must not be allowed to silently instruct host-side tools "
                "such as "
                "file read/write, shell, browser, or network actions without an explicit "
                "control boundary."
            ),
            graph_path=[
                f"entry {entry.name} ({entry.file}:{entry.line})",
                f"prompt/model call {prompt.name} ({prompt.file}:{prompt.line})",
                f"host tool/sink {tool.name} ({tool.file}:{tool.line})",
            ],
            evidence=[
                f"{prompt.file}:{prompt.line} calls model/prompt sink {prompt.name}",
                f"{tool.file}:{tool.line} calls host-side capability {tool.name}",
            ],
            proof_strategy=[
                "Feed benign untrusted content containing a canary tool instruction.",
                "Assert the model/tool bridge treats it as data, not an operator instruction.",
                (
                    "Verify sensitive tools require explicit allowlist/user approval and "
                    "scoped inputs."
                ),
            ],
        )
    ]


def _public_route_privileged_action(routes: list[Node], sinks: list[Node]) -> list[Candidate]:
    route = next((node for node in routes if node.attrs.get("public")), None)
    privileged = next(
        (node for node in sinks if node.attrs.get("capability") in PRIVILEGED_CAPABILITIES), None
    )
    if not route or not privileged:
        return []
    return [
        Candidate(
            id=f"public-route-privileged-{privileged.line}",
            title="Public route or webhook coexists with privileged action sink",
            pattern="public-webhook-route-auth-drift",
            severity_hint="medium",
            boundary="public HTTP/webhook caller -> privileged local/server action",
            violated_invariant=(
                "Public routes and webhooks should not reach privileged actions without "
                "explicit auth, "
                "signature verification, or operator opt-in."
            ),
            graph_path=[
                f"public {route.kind} {route.name} ({route.file}:{route.line})",
                f"privileged sink {privileged.name} ({privileged.file}:{privileged.line})",
            ],
            evidence=[
                f"{route.file}:{route.line} exposes public {route.kind} {route.name}",
                f"{privileged.file}:{privileged.line} calls privileged sink {privileged.name}",
            ],
            proof_strategy=[
                "Exercise the public route/webhook without credentials or signature headers.",
                "Assert privileged action is denied before any side effect.",
                "Add tests for both unauthenticated rejection and authenticated success paths.",
            ],
        )
    ]


def _is_remote_control_plane_command(command: Node) -> bool:
    if command.attrs.get("remote_invocable") is not True:
        return False
    if command.attrs.get("remote_admin_opt_in") is True:
        return False
    if command.name in CONTROL_PLANE_COMMAND_NAMES:
        return True
    lower_name = command.name.lower()
    return any(word in lower_name for word in ("resume", "summary", "session", "debug"))


def _direct_load_sink_for_command(graph: Graph, command: Node) -> Node | None:
    handler = _handler_for(graph, command)
    if handler:
        handler_sink = _direct_load_sink_called_by(graph, handler)
        if handler_sink:
            return handler_sink
        return None
    return _direct_load_sink_in_file(graph, command.file)


def _scope_for_command(graph: Graph, command: Node) -> Node | None:
    handler = _handler_for(graph, command)
    if handler:
        scope = _scope_used_by(graph, handler)
        if scope:
            return scope
    return _scope_in_file(graph, command.file)


def _direct_load_sink_called_by(graph: Graph, function: Node) -> Node | None:
    for edge in graph.edges:
        if edge.source != function.id or edge.kind != "calls":
            continue
        sink = graph.node_by_id(edge.target)
        if sink and sink.kind == "sink" and sink.name in DIRECT_LOAD_SINKS:
            return sink
    return None


def _scope_used_by(graph: Graph, function: Node) -> Node | None:
    for edge in graph.edges:
        if edge.source != function.id or edge.kind != "uses_scope":
            continue
        scope = graph.node_by_id(edge.target)
        if scope and scope.kind == "session_scope":
            return scope
    return None


def _direct_load_sink_in_file(graph: Graph, file: str) -> Node | None:
    return next(
        (
            node
            for node in graph.nodes
            if node.kind == "sink" and node.name in DIRECT_LOAD_SINKS and node.file == file
        ),
        None,
    )


def _scope_in_file(graph: Graph, file: str) -> Node | None:
    return next(
        (node for node in graph.nodes if node.kind == "session_scope" and node.file == file),
        None,
    )


def _candidate_id(command: Node, sink: Node) -> str:
    slug = command.name.strip("/").replace("/", "-") or "command"
    return f"{slug}-{sink.name}-{command.line}"


def _handler_for(graph: Graph, command: Node) -> Node | None:
    edge = next(
        (edge for edge in graph.edges if edge.source == command.id and edge.kind == "handled_by"),
        None,
    )
    return graph.node_by_id(edge.target) if edge else None


def _dedupe(candidates: list[Candidate]) -> list[Candidate]:
    seen: set[str] = set()
    unique: list[Candidate] = []
    for candidate in candidates:
        if candidate.id in seen:
            continue
        seen.add(candidate.id)
        unique.append(candidate)
    return unique
