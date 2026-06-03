from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from security_kg.schema import Edge, Graph, Node

COMMAND_FACTORY_NAMES = {"CommandSpec", "Command", "SlashCommand"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}
WEBHOOK_WORDS = {"webhook", "callback"}
SENSITIVE_CALL_NAMES = {
    "load_by_id",
    "get_by_id",
    "read_by_id",
    "resume",
    "summary",
    "filter",
    "where",
    "query",
    "select",
    "open",
    "write_text",
    "write_bytes",
    "copyfile",
    "extract",
    "extractall",
    "run",
    "system",
    "popen",
    "invoke_tool",
    "call_tool",
    "read_file",
    "write_file",
    "chat",
    "complete",
    "generate",
}
SESSION_SCOPE_PARTS = {"platform", "chat", "thread", "sender", "user", "tenant", "session", "owner"}
UNTRUSTED_PARAM_NAMES = {
    "id",
    "session_id",
    "job_id",
    "artifact_id",
    "file_id",
    "path",
    "filename",
    "name",
}
ENDPOINT_OVERRIDE_HINTS = (
    "HOST",
    "URL",
    "BASE_URL",
    "ENDPOINT",
    "QUOTA_URL",
    "USAGE_URL",
    "BILLING_URL",
    "API_URL",
)
ENDPOINT_OVERRIDE_EXCLUDE_HINTS = ("TOKEN_URL", "AUTH_URL", "OAUTH_URL")
CREDENTIAL_HINTS = ("COOKIE", "TOKEN", "API_KEY", "APIKEY", "SECRET", "AUTHORIZATION", "BEARER")
CREDENTIAL_CALL_HINTS = (
    "cookie",
    "token",
    "api_key",
    "apikey",
    "secret",
    "authorization",
    "bearer",
    "keychain",
    "browser",
    "credential",
)
HTTP_MODULE_NAMES = {"requests", "httpx", "urllib", "aiohttp"}
HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete", "request", "send"}
VALIDATION_HINTS = (
    "valid",
    "allowlist",
    "allow_list",
    "check",
    "enforce",
    "resolve",
    "canonical",
    "sanitize",
    "normalise",
    "normalize",
)
ENDPOINT_VALIDATION_TERMS = ("url", "host", "endpoint", "scheme")
PATH_VALIDATION_TERMS = (
    "path",
    "file",
    "filename",
    "archive",
    "member",
    "root",
    "base",
    "dir",
    "directory",
)


def map_repo(root: str | Path) -> Graph:
    """Map a repository into a small security-relevant graph."""
    repo_root = Path(root).resolve()
    graph = Graph(root=repo_root)
    for path in sorted(repo_root.rglob("*.py")):
        if any(part in {".venv", "venv", "__pycache__", ".git"} for part in path.parts):
            continue
        _map_python_file(graph, repo_root, path)
    return graph


def _map_python_file(graph: Graph, repo_root: Path, path: Path) -> None:
    rel = path.relative_to(repo_root).as_posix()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    except SyntaxError:
        return

    file_node = Node(id=f"file:{rel}", kind="file", name=rel, file=rel, attrs={"path": rel})
    graph.upsert_node(file_node)
    function_ids: dict[str, str] = {}
    pending_command_handlers: list[tuple[str, str]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_id = _function_id(rel, node.name, node.lineno)
            function_ids[node.name] = fn_id
            function = Node(
                id=fn_id,
                kind="function",
                name=node.name,
                file=rel,
                line=node.lineno,
                attrs={
                    "docstring": ast.get_docstring(node),
                    "args": [arg.arg for arg in node.args.args],
                },
            )
            graph.add_node(function)
            graph.add_edge(Edge(source=file_node.id, target=function.id, kind="defined_in"))
            _maybe_add_session_scope(graph, rel, node, function.id)
            _maybe_add_route_or_webhook(graph, rel, node, function.id)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            enclosing = _enclosing_function(tree, node)
            function_id = function_ids.get(enclosing.name) if enclosing else None

            command = _command_from_call(rel, node)
            if command is not None:
                graph.add_node(command)
                graph.add_edge(Edge(source=file_node.id, target=command.id, kind="defined_in"))
                handler = command.attrs.get("handler")
                if isinstance(handler, str):
                    pending_command_handlers.append((command.id, handler))

            sink = _sink_from_call(rel, node, enclosing)
            if sink is not None:
                graph.add_node(sink)
                graph.add_edge(Edge(source=f"file:{rel}", target=sink.id, kind="evidence"))
                if function_id:
                    graph.add_edge(Edge(source=function_id, target=sink.id, kind="calls"))

            provider_node = _provider_endpoint_control_from_call(rel, node, enclosing)
            if provider_node is not None:
                graph.add_node(provider_node)
                graph.add_edge(
                    Edge(source=file_node.id, target=provider_node.id, kind="defined_in")
                )
                if function_id:
                    graph.add_edge(
                        Edge(source=function_id, target=provider_node.id, kind="uses_endpoint")
                    )

            credential_node = _credential_source_from_call(rel, node, enclosing)
            if credential_node is not None:
                graph.add_node(credential_node)
                graph.add_edge(
                    Edge(source=file_node.id, target=credential_node.id, kind="defined_in")
                )
                if function_id:
                    graph.add_edge(
                        Edge(
                            source=function_id,
                            target=credential_node.id,
                            kind="resolves_credential",
                        )
                    )

            request_node = _request_sink_from_call(rel, node, enclosing)
            if request_node is not None:
                graph.add_node(request_node)
                graph.add_edge(Edge(source=file_node.id, target=request_node.id, kind="defined_in"))
                if function_id:
                    graph.add_edge(
                        Edge(source=function_id, target=request_node.id, kind="sends_request")
                    )

            validation_node = _validation_guard_from_call(rel, node, enclosing)
            if validation_node is not None:
                graph.add_node(validation_node)
                graph.add_edge(
                    Edge(source=file_node.id, target=validation_node.id, kind="defined_in")
                )
                if function_id:
                    graph.add_edge(
                        Edge(source=function_id, target=validation_node.id, kind="guarded_by")
                    )

    for command_id, handler_name in pending_command_handlers:
        handler_id = function_ids.get(handler_name)
        if handler_id:
            graph.add_edge(Edge(source=command_id, target=handler_id, kind="handled_by"))


def _function_id(rel: str, name: str, line: int) -> str:
    return f"function:{rel}:{name}:{line}"


def _enclosing_function(
    tree: ast.AST, target: ast.AST
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    # The AST has no parent pointers; this small walk is fine for MVP-sized source mapping.
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(child is target for child in ast.walk(node)):
            return node
    return None


def _command_from_call(rel: str, node: ast.Call) -> Node | None:
    name = _call_name(node.func)
    if name not in COMMAND_FACTORY_NAMES:
        return None

    attrs: dict[str, Any] = {}
    command_name = None
    for keyword in node.keywords:
        if keyword.arg is None:
            continue
        value = _literal(keyword.value)
        attrs[keyword.arg] = value
        if keyword.arg in {"name", "command", "trigger"} and isinstance(value, str):
            command_name = value

    if command_name is None and node.args:
        first = _literal(node.args[0])
        if isinstance(first, str):
            command_name = first

    if not command_name:
        return None

    attrs.setdefault("remote_invocable", False)
    attrs.setdefault("remote_admin_opt_in", False)
    return Node(
        id=f"command:{rel}:{command_name}:{node.lineno}",
        kind="command",
        name=command_name,
        file=rel,
        line=node.lineno,
        attrs=attrs,
    )


def _sink_from_call(
    rel: str,
    node: ast.Call,
    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> Node | None:
    name = _call_name(node.func)
    if name not in SENSITIVE_CALL_NAMES:
        return None
    capability = _capability_for_sink(name)
    args_text = [_safe_unparse(arg) for arg in node.args]
    kwargs = {kw.arg: _safe_unparse(kw.value) for kw in node.keywords if kw.arg}
    function_args = [arg.arg for arg in enclosing.args.args] if enclosing else []
    return Node(
        id=f"sink:{rel}:{name}:{node.lineno}:{node.col_offset}",
        kind="sink",
        name=name,
        file=rel,
        line=node.lineno,
        attrs={
            "capability": capability,
            "args": args_text,
            "kwargs": kwargs,
            "enclosing_function": enclosing.name if enclosing else None,
            "function_args": function_args,
            "uses_untrusted_param": bool(set(function_args) & UNTRUSTED_PARAM_NAMES),
        },
    )


def _maybe_add_session_scope(
    graph: Graph,
    rel: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_id: str,
) -> None:
    parts: set[str] = set()
    arg_names = {arg.arg for arg in node.args.args}
    if "key" in node.name or "scope" in node.name or "session" in node.name:
        parts |= arg_names & SESSION_SCOPE_PARTS

    for child in ast.walk(node):
        if isinstance(child, ast.JoinedStr):
            text = ast.unparse(child) if hasattr(ast, "unparse") else ""
            parts |= {part for part in SESSION_SCOPE_PARTS if part in text}
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts |= {part for part in SESSION_SCOPE_PARTS if part in child.value}

    if len(parts) >= 2 and ({"sender", "user", "tenant", "owner"} & parts):
        scope = Node(
            id=f"session_scope:{rel}:{node.name}:{node.lineno}",
            kind="session_scope",
            name=node.name,
            file=rel,
            line=node.lineno,
            attrs={"parts": sorted(parts)},
        )
        graph.add_node(scope)
        graph.add_edge(Edge(source=function_id, target=scope.id, kind="uses_scope"))


def _maybe_add_route_or_webhook(
    graph: Graph,
    rel: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_id: str,
) -> None:
    public = False
    route_path = None
    for decorator in node.decorator_list:
        call = decorator if isinstance(decorator, ast.Call) else None
        func = call.func if call else decorator
        name = _call_name(func)
        if name in ROUTE_DECORATORS:
            public = True
            if call and call.args:
                route_path = _literal(call.args[0])
        text = _safe_unparse(decorator).lower()
        if any(word in text for word in WEBHOOK_WORDS):
            public = True
            route_path = route_path or f"/{node.name}"
    if any(word in node.name.lower() for word in WEBHOOK_WORDS):
        public = True
        route_path = route_path or f"/{node.name}"
    if public:
        kind = (
            "webhook"
            if any(word in (route_path or node.name).lower() for word in WEBHOOK_WORDS)
            else "route"
        )
        route = Node(
            id=f"{kind}:{rel}:{node.name}:{node.lineno}",
            kind=kind,
            name=str(route_path or node.name),
            file=rel,
            line=node.lineno,
            attrs={"handler": node.name, "public": True},
        )
        graph.add_node(route)
        graph.add_edge(Edge(source=route.id, target=function_id, kind="handled_by"))


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _dotted_call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = _dotted_call_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return ""


def _provider_endpoint_control_from_call(
    rel: str,
    node: ast.Call,
    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> Node | None:
    env_name = _environment_key_from_call(node)
    if not env_name or not _looks_like_endpoint_override(env_name):
        return None
    return Node(
        id=f"provider_endpoint_control:{rel}:{env_name}:{node.lineno}:{node.col_offset}",
        kind="provider_endpoint_control",
        name=env_name,
        file=rel,
        line=node.lineno,
        attrs={
            "source": "environment",
            "expression": _safe_unparse(node),
            "enclosing_function": enclosing.name if enclosing else None,
        },
    )


def _credential_source_from_call(
    rel: str,
    node: ast.Call,
    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> Node | None:
    env_name = _environment_key_from_call(node)
    call_text = _dotted_call_name(node.func).lower()
    expression = _safe_unparse(node)
    if env_name and any(hint in env_name.upper() for hint in CREDENTIAL_HINTS):
        name = env_name
        source = "environment"
    elif any(hint in call_text for hint in CREDENTIAL_CALL_HINTS):
        name = _dotted_call_name(node.func)
        source = "call"
    else:
        return None
    return Node(
        id=f"credential_source:{rel}:{name}:{node.lineno}:{node.col_offset}",
        kind="credential_source",
        name=name,
        file=rel,
        line=node.lineno,
        attrs={
            "source": source,
            "expression": expression,
            "enclosing_function": enclosing.name if enclosing else None,
        },
    )


def _request_sink_from_call(
    rel: str,
    node: ast.Call,
    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> Node | None:
    dotted = _dotted_call_name(node.func)
    parts = dotted.split(".")
    if not parts:
        return None
    call_name = parts[-1]
    module = parts[0]
    expression = _safe_unparse(node)
    if module not in HTTP_MODULE_NAMES and call_name not in {"urlopen"}:
        return None
    if call_name not in HTTP_METHOD_NAMES and call_name != "urlopen":
        return None
    return Node(
        id=f"request_sink:{rel}:{dotted}:{node.lineno}:{node.col_offset}",
        kind="request_sink",
        name=dotted,
        file=rel,
        line=node.lineno,
        attrs={
            "expression": expression,
            "enclosing_function": enclosing.name if enclosing else None,
            "args": [_safe_unparse(arg) for arg in node.args],
            "kwargs": {kw.arg: _safe_unparse(kw.value) for kw in node.keywords if kw.arg},
            "mentions_sensitive_header": any(
                hint.lower() in expression.lower() for hint in CREDENTIAL_CALL_HINTS
            ),
        },
    )


def _validation_guard_from_call(
    rel: str,
    node: ast.Call,
    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> Node | None:
    name = _dotted_call_name(node.func)
    lower = name.lower()
    expression = _safe_unparse(node)
    expression_lower = expression.lower()
    if not any(hint in lower for hint in VALIDATION_HINTS):
        return None

    categories = []
    if any(term in expression_lower for term in ENDPOINT_VALIDATION_TERMS):
        categories.append("endpoint")
    if any(term in expression_lower for term in PATH_VALIDATION_TERMS):
        categories.append("path")
    if not categories:
        return None

    return Node(
        id=f"validation_guard:{rel}:{name}:{node.lineno}:{node.col_offset}",
        kind="validation_guard",
        name=name,
        file=rel,
        line=node.lineno,
        attrs={
            "expression": expression,
            "categories": categories,
            "enclosing_function": enclosing.name if enclosing else None,
        },
    )


def _environment_key_from_call(node: ast.Call) -> str | None:
    dotted = _dotted_call_name(node.func)
    reads_environment = (
        dotted.endswith("os.getenv") or dotted.endswith("environ.get") or dotted == "getenv"
    )
    if reads_environment and node.args:
        value = _literal(node.args[0])
        return value if isinstance(value, str) else None
    return None


def _looks_like_endpoint_override(name: str) -> bool:
    upper = name.upper()
    if any(excluded in upper for excluded in ENDPOINT_OVERRIDE_EXCLUDE_HINTS):
        return False
    return any(upper.endswith(hint) or f"_{hint}_" in upper for hint in ENDPOINT_OVERRIDE_HINTS)


def _literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        return None


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - py39 fallback edge cases
        return ""


def _capability_for_sink(name: str) -> str:
    if name in {"load_by_id", "get_by_id", "read_by_id"}:
        return "direct_object_load"
    if name in {"filter", "where", "query", "select"}:
        return "scoped_query"
    if name in {"open", "write_text", "write_bytes", "copyfile", "extract", "extractall"}:
        return "filesystem_write"
    if name in {"run", "system", "popen"}:
        return "shell_execution"
    if name in {"invoke_tool", "call_tool", "read_file", "write_file"}:
        return "host_tool"
    if name in {"chat", "complete", "generate"}:
        return "llm_prompt"
    if name in {"resume", "summary"}:
        return "session_control_plane"
    return "sensitive_operation"
