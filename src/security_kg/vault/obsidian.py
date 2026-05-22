from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - dependency fallback for minimal installs
    yaml = None  # type: ignore[assignment]

FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
WIKILINK_RE = re.compile(r"(?<!!)\[\[([^\]|#]+)(?:#[^\]|]+)?(?:\|[^\]]+)?\]\]")
TAG_RE = re.compile(r"(?<!\w)#([A-Za-z][A-Za-z0-9_/-]*)")
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
GITHUB_URL_RE = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./#?=&%-]+)?"
)
PR_URL_RE = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/(\d+)")


@dataclass
class Note:
    path: Path
    rel_path: str
    title: str
    body: str
    frontmatter: dict[str, Any]
    wikilinks: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    cwes: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    github_urls: set[str] = field(default_factory=set)
    pr_urls: set[str] = field(default_factory=set)
    kind: str = "note"


def iter_markdown(vault: Path, include_dirs: list[str] | None = None) -> list[Path]:
    roots = [vault / directory for directory in include_dirs] if include_dirs else [vault]
    paths: list[Path] = []
    for root in roots:
        if root.exists():
            paths.extend(path for path in root.rglob("*.md") if ".obsidian" not in path.parts)
    return sorted(paths)


def parse_note(path: Path, vault: Path) -> Note:
    raw = path.read_text(encoding="utf-8")
    frontmatter: dict[str, Any] = {}
    body = raw
    match = FRONTMATTER_RE.match(raw)
    if match:
        frontmatter = _parse_frontmatter(match.group(1))
        body = raw[match.end() :]

    scan_body = _strip_code_blocks(body)
    rel_path = path.relative_to(vault).as_posix()
    title = path.stem
    kind = str(frontmatter.get("type") or infer_kind(rel_path, title, frontmatter)).lower()

    tags = {tag.strip("#") for tag in _as_string_set(frontmatter.get("tags"))}
    tags.update(TAG_RE.findall(scan_body))

    cwes = {cwe.upper() for cwe in CWE_RE.findall(scan_body)}
    cwes.update({cwe.upper() for cwe in _as_string_set(frontmatter.get("cwe"))})

    cves = {cve.upper() for cve in CVE_RE.findall(scan_body)}
    cves.update({cve.upper() for cve in _as_string_set(frontmatter.get("cve"))})

    github_urls = set(GITHUB_URL_RE.findall(scan_body))
    github_urls.update(_as_string_set(frontmatter.get("repo")))
    github_urls.update(_as_string_set(frontmatter.get("github")))

    pr_urls = {match.group(0) for match in PR_URL_RE.finditer(scan_body)}
    pr_urls.update(_as_string_set(frontmatter.get("pr")))

    wikilinks = {link.strip() for link in WIKILINK_RE.findall(scan_body) if link.strip()}
    target = frontmatter.get("target")
    if target:
        wikilinks.add(str(target).strip())

    return Note(
        path=path,
        rel_path=rel_path,
        title=title,
        body=body,
        frontmatter=frontmatter,
        wikilinks=wikilinks,
        tags=tags,
        cwes=cwes,
        cves=cves,
        github_urls=github_urls,
        pr_urls=pr_urls,
        kind=kind,
    )


def infer_kind(rel_path: str, title: str, frontmatter: dict[str, Any]) -> str:
    lower_path = rel_path.lower()
    lower_title = title.lower()
    if "finding" in lower_path or lower_title.startswith("finding -"):
        return "finding"
    if "target" in lower_path or lower_title.startswith("target -"):
        return "target"
    if frontmatter.get("status") or frontmatter.get("severity"):
        return "finding"
    return "note"


def _parse_frontmatter(text: str) -> dict[str, Any]:
    if yaml is not None:
        loaded = yaml.safe_load(text) or {}
        return loaded if isinstance(loaded, dict) else {}
    data: dict[str, Any] = {}
    for line in text.splitlines():
        if ":" not in line or line.startswith(" "):
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip('"\'')
    return data


def _strip_code_blocks(text: str) -> str:
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    return re.sub(r"`[^`]*`", "", text)


def _as_string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value.strip()} if value.strip() else set()
    if isinstance(value, (list, tuple, set)):
        return {str(item).strip() for item in value if str(item).strip()}
    return {str(value).strip()} if str(value).strip() else set()
