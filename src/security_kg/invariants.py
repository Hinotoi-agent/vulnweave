from __future__ import annotations

from security_kg.schema import Candidate, Graph, Node

CONTROL_PLANE_COMMAND_NAMES = {"/resume", "/summary", "/debug", "/config", "/shell", "/tools"}
DIRECT_LOAD_SINKS = {"load_by_id", "get_by_id", "read_by_id"}
PRIVILEGED_CAPABILITIES = {"direct_object_load", "filesystem_write", "shell_execution", "host_tool"}
COMMAND_PARAM_HINTS = {"cmd", "command", "shell", "args", "argv"}
URL_PARAM_HINTS = {"url", "uri", "endpoint", "target", "callback", "webhook"}


def find_candidates(graph: Graph) -> list[Candidate]:
    candidates: list[Candidate] = []
    commands = [node for node in graph.nodes if node.kind == "command"]
    routes = [node for node in graph.nodes if node.kind in {"route", "webhook"}]
    sinks = [node for node in graph.nodes if node.kind == "sink"]
    scopes = [node for node in graph.nodes if node.kind == "session_scope"]
    endpoint_controls = [node for node in graph.nodes if node.kind == "provider_endpoint_control"]
    credential_sources = [node for node in graph.nodes if node.kind == "credential_source"]
    request_sinks = [node for node in graph.nodes if node.kind == "request_sink"]
    validation_guards = [node for node in graph.nodes if node.kind == "validation_guard"]

    candidates.extend(_remote_command_direct_load(graph, commands, sinks, scopes))
    candidates.extend(_list_filter_direct_load_drift(sinks, scopes))
    candidates.extend(_bearer_handle_ownership_gap(sinks, commands, routes, scopes))
    candidates.extend(_upload_write_path_risk(sinks, commands, routes, validation_guards))
    candidates.extend(_prompt_tool_boundary_risk(sinks, commands, routes))
    candidates.extend(_public_route_privileged_action(routes, sinks))
    candidates.extend(_untrusted_shell_execution_risk(sinks, commands, routes))
    candidates.extend(
        _untrusted_url_request_risk(request_sinks, commands, routes, validation_guards)
    )
    candidates.extend(
        _provider_endpoint_credential_exfil(
            endpoint_controls, credential_sources, request_sinks, validation_guards
        )
    )
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
    sinks: list[Node], commands: list[Node], routes: list[Node], validation_guards: list[Node]
) -> list[Candidate]:
    fs = next((node for node in sinks if node.attrs.get("capability") == "filesystem_write"), None)
    if not fs:
        return []
    entry = (routes or commands or [fs])[0]
    path_guard = _path_validation_guard_for_sink(fs, validation_guards)
    if path_guard is not None:
        return [
            Candidate(
                id=f"validated-path-reopened-write-{fs.line}",
                title="Validated path is later reopened by pathname for filesystem write",
                pattern="validated-path-reopen-toctou-write-risk",
                severity_hint="high",
                boundary=(
                    "uploaded/path parameter -> validation-only path check -> host filesystem write"
                ),
                violated_invariant=(
                    "Path containment checks must stay coupled to the eventual write operation; "
                    "validating a pathname and later reopening it can leave traversal, symlink, "
                    "or rename races unless the write is anchored with dir_fd/openat/O_NOFOLLOW "
                    "or equivalent primitives."
                ),
                graph_path=[
                    f"entry {entry.name} ({entry.file}:{entry.line})",
                    f"path guard {path_guard.name} ({path_guard.file}:{path_guard.line})",
                    f"filesystem sink {fs.name} ({fs.file}:{fs.line})",
                ],
                evidence=[
                    (
                        f"{path_guard.file}:{path_guard.line} applies path validation guard "
                        f"{path_guard.name}: {path_guard.attrs.get('expression')}"
                    ),
                    (
                        f"{fs.file}:{fs.line} later calls filesystem sink {fs.name} with "
                        f"arguments {fs.attrs.get('args')}"
                    ),
                    (
                        "A validation guard before a path-based write is review-worthy "
                        "unless the code proves the validated handle, not just the "
                        "validated string, is used."
                    ),
                ],
                proof_strategy=[
                    (
                        "Build a temp-root fixture with an attacker-controlled path under "
                        "the allowed base."
                    ),
                    (
                        "Attempt traversal, symlink, and rename-after-validation cases before the "
                        "write/extract call."
                    ),
                    (
                        "Assert writes are anchored under the expected base directory and cannot "
                        "clobber existing files outside it."
                    ),
                    (
                        "Prefer regression tests around fd-anchored openat/dir_fd/O_NOFOLLOW or "
                        "atomic temp-file-and-rename flows."
                    ),
                ],
            )
        ]
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


def _untrusted_shell_execution_risk(
    sinks: list[Node], commands: list[Node], routes: list[Node]
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for sink in sinks:
        if sink.attrs.get("capability") != "shell_execution":
            continue
        function_args = set(sink.attrs.get("function_args") or [])
        sink_args = " ".join(sink.attrs.get("args") or [])
        commandish_args = sorted(function_args & COMMAND_PARAM_HINTS)
        if not commandish_args and not any(arg and arg in sink_args for arg in function_args):
            continue
        entry = _entry_for_function(commands, routes, sink) or (routes or commands or [sink])[0]
        candidates.append(
            Candidate(
                id=f"untrusted-shell-execution-{sink.file}-{sink.line}",
                title="Caller-controlled command data can reach shell execution",
                pattern="untrusted-command-shell-execution-risk",
                severity_hint="high",
                boundary=(
                    "untrusted route/command parameter -> shell command construction -> "
                    "host process"
                ),
                violated_invariant=(
                    "Untrusted parameters must not be passed to shell/process execution without "
                    "strict argument separation, allowlisting, and shell=False-style execution."
                ),
                graph_path=[
                    f"entry {entry.name} ({entry.file}:{entry.line})",
                    f"shell sink {sink.name} ({sink.file}:{sink.line})",
                ],
                evidence=[
                    (
                        f"{sink.file}:{sink.line} calls shell execution sink {sink.name} "
                        f"with arguments {sink.attrs.get('args')}"
                    ),
                    (
                        "The enclosing function exposes command-like parameters "
                        f"{sorted(function_args)}."
                    ),
                ],
                proof_strategy=[
                    (
                        "Exercise the route/command with a benign metacharacter canary "
                        "such as '; echo VULNWEAVE'."
                    ),
                    "Assert inputs are parsed as data, not concatenated shell syntax.",
                    (
                        "Prefer tests that verify argv-list execution, allowlisted "
                        "subcommands, and shell=False."
                    ),
                ],
            )
        )
    return candidates


def _untrusted_url_request_risk(
    request_sinks: list[Node],
    commands: list[Node],
    routes: list[Node],
    validation_guards: list[Node],
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for request in request_sinks:
        function_args = set(request.attrs.get("function_args") or [])
        urlish_args = sorted(function_args & URL_PARAM_HINTS)
        request_args = " ".join(request.attrs.get("args") or [])
        if not urlish_args and not any(
            arg and arg in request_args for arg in function_args & URL_PARAM_HINTS
        ):
            continue
        if _endpoint_validation_guard_before(request, validation_guards) is not None:
            continue
        entry = (
            _entry_for_function(commands, routes, request) or (routes or commands or [request])[0]
        )
        candidates.append(
            Candidate(
                id=f"untrusted-url-request-{request.file}-{request.line}",
                title="Caller-controlled URL can reach outbound HTTP request",
                pattern="untrusted-url-outbound-request-ssrf-risk",
                severity_hint="high",
                boundary=(
                    "untrusted route/command URL parameter -> server-side outbound "
                    "HTTP request"
                ),
                violated_invariant=(
                    "URLs supplied by remote actors must be constrained before server-side "
                    "requests so callers cannot pivot through internal metadata services, local "
                    "admin endpoints, or unintended schemes."
                ),
                graph_path=[
                    f"entry {entry.name} ({entry.file}:{entry.line})",
                    f"HTTP request sink {request.name} ({request.file}:{request.line})",
                ],
                evidence=[
                    (
                        f"{request.file}:{request.line} builds/sends an HTTP request via "
                        f"{request.name} with arguments {request.attrs.get('args')}"
                    ),
                    (
                        "The enclosing function exposes URL-like parameters "
                        f"{sorted(function_args & URL_PARAM_HINTS)}."
                    ),
                    "No endpoint validation guard was detected before the request sink.",
                ],
                proof_strategy=[
                    (
                        "Point the URL parameter at a local listener and confirm whether "
                        "the server connects."
                    ),
                    (
                        "Try blocked targets such as localhost, link-local metadata IPs, "
                        "file-like schemes, and redirects."
                    ),
                    (
                        "Add regression tests for scheme, host/IP, DNS rebinding, "
                        "redirect, and credential-forwarding controls."
                    ),
                ],
            )
        )
    return candidates


def _entry_for_function(commands: list[Node], routes: list[Node], sink: Node) -> Node | None:
    function_name = sink.attrs.get("enclosing_function")
    if not function_name:
        return None
    return next(
        (
            node
            for node in [*routes, *commands]
            if node.attrs.get("handler") == function_name or node.name == function_name
        ),
        None,
    )


def _endpoint_validation_guard_before(sink: Node, validation_guards: list[Node]) -> Node | None:
    sink_function = sink.attrs.get("enclosing_function")
    guards = [
        node
        for node in validation_guards
        if node.file == sink.file
        and "endpoint" in node.attrs.get("categories", [])
        and (not sink_function or node.attrs.get("enclosing_function") in {sink_function, None})
        and node.line <= sink.line
    ]
    return max(guards, key=lambda node: node.line) if guards else None


def _path_validation_guard_for_sink(sink: Node, validation_guards: list[Node]) -> Node | None:
    sink_function = sink.attrs.get("enclosing_function")
    guards = [
        node
        for node in validation_guards
        if node.file == sink.file
        and "path" in node.attrs.get("categories", [])
        and (not sink_function or node.attrs.get("enclosing_function") in {sink_function, None})
        and node.line <= sink.line
    ]
    return max(guards, key=lambda node: node.line) if guards else None


def _provider_endpoint_credential_exfil(
    endpoint_controls: list[Node],
    credential_sources: list[Node],
    request_sinks: list[Node],
    validation_guards: list[Node],
) -> list[Candidate]:
    candidates: list[Candidate] = []
    for endpoint in endpoint_controls:
        function_name = endpoint.attrs.get("enclosing_function")
        same_file_credentials = [node for node in credential_sources if node.file == endpoint.file]
        same_file_requests = [node for node in request_sinks if node.file == endpoint.file]
        credentials = [
            node
            for node in same_file_credentials
            if function_name and node.attrs.get("enclosing_function") == function_name
        ] or same_file_credentials
        requests = [
            node
            for node in same_file_requests
            if function_name and node.attrs.get("enclosing_function") == function_name
        ] or same_file_requests
        if not credentials or not requests:
            continue

        credential = min(credentials, key=lambda node: node.line)
        request = min(requests, key=lambda node: node.line)
        guards = [
            node
            for node in validation_guards
            if node.file == endpoint.file
            and "endpoint" in node.attrs.get("categories", [])
            and (not function_name or node.attrs.get("enclosing_function") in {function_name, None})
        ]
        guard_before_credential = next(
            (node for node in guards if endpoint.line <= node.line < credential.line), None
        )
        if guard_before_credential is not None:
            # Validation before credential discovery matches the desired invariant;
            # keep this as graph evidence but do not emit a review candidate.
            continue

        candidates.append(
            Candidate(
                id=f"provider-endpoint-credential-exfil-{endpoint.file}-{endpoint.line}",
                title="Provider endpoint override can reach credentialed request construction",
                pattern="provider-endpoint-override-secret-exfiltration",
                severity_hint="high",
                boundary=(
                    "local/config/environment-controlled provider endpoint -> "
                    "browser/API/keychain credential -> outbound provider request"
                ),
                violated_invariant=(
                    "Provider HOST/URL overrides that influence credentialed usage or billing "
                    "requests must be validated before cookie, API-key, bearer-token, browser, "
                    "or keychain credential discovery and before constructing the outbound request."
                ),
                graph_path=[
                    f"endpoint override {endpoint.name} ({endpoint.file}:{endpoint.line})",
                    f"credential source {credential.name} ({credential.file}:{credential.line})",
                    f"request sink {request.name} ({request.file}:{request.line})",
                ],
                evidence=[
                    f"{endpoint.file}:{endpoint.line} reads endpoint override {endpoint.name}",
                    (
                        f"{credential.file}:{credential.line} resolves credential "
                        f"material via {credential.name}"
                    ),
                    (
                        f"{request.file}:{request.line} builds/sends an HTTP "
                        f"request via {request.name}"
                    ),
                    (
                        "No validation guard was detected between endpoint override resolution and "
                        "credential discovery in the mapped function/file."
                    ),
                ],
                proof_strategy=[
                    (
                        "Set the provider HOST/URL override to a local listener "
                        "using an explicit http:// URL."
                    ),
                    (
                        "Configure only dummy/redacted provider credentials or "
                        "use an isolated test cookie/API key; never publish real values."
                    ),
                    (
                        "Trigger the provider usage/billing fetch and assert the invalid endpoint "
                        "fails closed before credential discovery or request construction."
                    ),
                    (
                        "If any request reaches the listener, record which sensitive header class "
                        "arrived and redact the actual value."
                    ),
                    (
                        "Add a regression test proving validation happens before browser/keychain/"
                        "config credential lookup for every provider mode."
                    ),
                ],
            )
        )
    return candidates


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
