#!/usr/bin/env python3
# Read local MCP client configs and flag known-bad package versions.
# Read-only. The standard library is enough. Does not install or start a server.
# Authorized defensive use only.
# Digital Fortress — MCP Config Advisory Check

"""Read MCP client config files and check launched packages.

The script reads JSON you already have. It does not install, download, or
start an MCP server, and it does not edit the config. Use it on files and
machines you own or are explicitly allowed to assess.

Online mode (the default) sends one POST per pinned package to the OSV query
API and merges that answer with ``advisory_snapshot.json``. ``--offline``
uses the snapshot only and does not open a network connection.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from functools import total_ordering
from pathlib import Path
from typing import Any

__version__ = "0.1.0"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_MAX_BODY = 2_000_000
_MAX_PAGES = 10
_DEFAULT_TIMEOUT = 20.0

DEFAULT_SNAPSHOT = Path(__file__).resolve().parent / "advisory_snapshot.json"

_CONFIG_FILENAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
_SERVER_KEYS = ("mcpServers", "servers")
_ECOSYSTEMS = {"npm", "PyPI"}
_KINDS = {"malicious-package", "vulnerable-version"}
_CONTAINER_COMMANDS = {"docker", "podman", "nerdctl"}

_PRE_ORDER = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2}
_VERSION_RE = re.compile(
    r"""
    ^
    (?:(?P<epoch>[0-9]+)!)??
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:
        [-_.]?
        (?P<pre_l>alpha|beta|rc|a|b|c)
        [-_.]?
        (?P<pre_n>[0-9]+)?
    )?
    (?:
        [-_.]?
        (?P<post_l>post|rev|r)
        [-_.]?
        (?P<post_n>[0-9]+)?
    )?
    (?:
        [-_.]?
        (?P<dev_l>dev)
        [-_.]?
        (?P<dev_n>[0-9]+)?
    )?
    $
    """,
    re.IGNORECASE | re.VERBOSE,
)
_RANGE_OP_RE = re.compile(r"^(===|==|~=|!=|<=|>=|<|>)\s*(.+)$")
_PYPI_SPEC_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[[^\[\]]+\])?"
    r"(?P<rest>.*)$"
)
_NPM_NAME_RE = re.compile(r"^@?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)?$")
_PYTHON_RE = re.compile(r"^(?:python(?:\d+(?:\.\d+)?)?|py)$")
_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")

_NPX_TAKES_VALUE = {
    "--package",
    "-p",
    "--call",
    "-c",
    "--registry",
    "--userconfig",
    "--cache",
    "--npm",
    "--node-arg",
    "--node-options",
    "--workspace",
    "-w",
}
_UVX_TAKES_VALUE = {
    "--from",
    "--with",
    "--with-editable",
    "--python",
    "-p",
    "--index",
    "--default-index",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--config-file",
    "--python-preference",
    "--directory",
    "--project",
    "--cache-dir",
    "--constraint",
    "-c",
    "--override",
    "--exclude-newer",
    "--link-mode",
    "--refresh-package",
    "--prerelease",
    "--index-strategy",
    "--keyring-provider",
    "--color",
    "--prefix",
    "--python-platform",
    "--managed-python",
}
_PIPX_TAKES_VALUE = {
    "--python",
    "--pip-args",
    "--index-url",
    "-i",
    "--spec",
    "--suffix",
}
_PIP_TAKES_VALUE = {
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-t",
    "--target",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--find-links",
    "-f",
    "-d",
    "--dest",
    "--prefix",
    "--root",
    "--src",
    "--upgrade-strategy",
    "--implementation",
    "--python-version",
    "--abi",
    "--platform",
    "--config-settings",
    "-C",
    "--global-option",
    "--no-binary",
    "--only-binary",
    "--progress-bar",
    "--log",
    "--proxy",
    "--cert",
    "--client-cert",
    "--cache-dir",
    "--timeout",
    "--exists-action",
    "--trusted-host",
    "--use-feature",
    "--use-deprecated",
    "--report",
    "-b",
    "--build",
    "--build-option",
}


class CheckError(Exception):
    """A config, snapshot, or query problem that blocks a reliable check."""


class NotAPackageLaunch(Exception):
    """The command is a known launcher but does not name a package."""


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise CheckError(f"refused an OSV redirect ({code})")


_OPENER = urllib.request.build_opener(_RefuseRedirect)


@total_ordering
class Version:
    """A small subset of PEP 440, enough for the bundled ranges."""

    __slots__ = ("epoch", "release", "pre", "post", "dev", "text")

    def __init__(
        self,
        text: str,
        epoch: int,
        release: tuple[int, ...],
        pre: tuple[int, int] | None,
        post: int | None,
        dev: int | None,
    ) -> None:
        self.text = text
        self.epoch = epoch
        self.release = release
        self.pre = pre
        self.post = post
        self.dev = dev

    def _key(self) -> tuple[Any, ...]:
        release = list(self.release)
        while len(release) > 1 and release[-1] == 0:
            release.pop()
        if self.dev is not None and self.pre is None and self.post is None:
            pre_key = (-1, 0)
        elif self.pre is None:
            pre_key = (99, 0)
        else:
            pre_key = self.pre
        post_key = -1 if self.post is None else self.post
        dev_key = 10**18 if self.dev is None else self.dev
        return (self.epoch, tuple(release), pre_key, post_key, dev_key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() == other._key()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __repr__(self) -> str:
        return f"Version({self.text!r})"


def parse_version(text: str) -> Version:
    """Parse one version. Raise CheckError when it is not usable."""
    raw = text.strip()
    if len(raw) >= 2 and raw[0] in "vV" and raw[1].isdigit():
        raw = raw[1:]
    raw = raw.split("+", 1)[0]
    match = _VERSION_RE.match(raw)
    if match is None:
        raise CheckError(f"not a version: {text}")
    epoch = int(match.group("epoch") or 0)
    release = tuple(int(part) for part in match.group("release").split("."))
    pre = None
    if match.group("pre_l"):
        label = match.group("pre_l").lower()
        pre = (_PRE_ORDER[label], int(match.group("pre_n") or 0))
    post = None
    if match.group("post_l"):
        post = int(match.group("post_n") or 0)
    dev = None
    if match.group("dev_l"):
        dev = int(match.group("dev_n") or 0)
    return Version(text, epoch, release, pre, post, dev)


def version_matches(version: str, spec: str) -> bool:
    """Return True when ``version`` satisfies every comma-separated constraint."""
    constraints = [part.strip() for part in spec.split(",") if part.strip()]
    if not constraints:
        raise CheckError("empty affected range")
    got = parse_version(version)
    for constraint in constraints:
        match = _RANGE_OP_RE.match(constraint)
        if match is None:
            raise CheckError(f"bad range constraint: {constraint}")
        op, raw = match.group(1), match.group(2).strip()
        if "*" in raw:
            raise CheckError(f"wildcard range is not supported: {constraint}")
        want = parse_version(raw)
        if op in {"==", "==="}:
            ok = got == want
        elif op == "!=":
            ok = got != want
        elif op == "<":
            ok = got < want
        elif op == "<=":
            ok = got <= want
        elif op == ">":
            ok = got > want
        elif op == ">=":
            ok = got >= want
        elif op == "~=":
            ok = _compatible(got, want)
        else:
            raise CheckError(f"bad range operator: {op}")
        if not ok:
            return False
    return True


def _compatible(got: Version, want: Version) -> bool:
    if len(want.release) < 2:
        raise CheckError("compatible release needs at least two numeric components")
    if got.epoch != want.epoch or got < want:
        return False
    prefix = want.release[:-1]
    if len(got.release) < len(prefix):
        return False
    return got.release[: len(prefix)] == prefix


def _validate_range(spec: str, ident: str) -> None:
    constraints = [part.strip() for part in spec.split(",") if part.strip()]
    if not constraints:
        raise CheckError(f"{ident} has an empty affected range")
    for constraint in constraints:
        match = _RANGE_OP_RE.match(constraint)
        if match is None or "*" in match.group(2):
            raise CheckError(f"{ident} has a bad affected range: {spec}")
        parse_version(match.group(2).strip())


def normalize_name(name: str, ecosystem: str) -> str:
    """Compare npm names case-insensitively and PyPI names per PEP 503."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def program_name(command: str) -> str:
    base = command.replace("\\", "/").rstrip("/").split("/")[-1].lower()
    for suffix in (".cmd", ".exe", ".bat"):
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def claude_config_path() -> Path:
    """Claude Desktop config for this OS. Honors ``XDG_CONFIG_HOME`` on Linux."""
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        root = Path(appdata) if appdata else home / "AppData" / "Roaming"
        return root / "Claude" / "claude_desktop_config.json"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg) if xdg else home / ".config"
    return root / "Claude" / "claude_desktop_config.json"


def default_paths() -> list[Path]:
    cwd = Path.cwd()
    candidates = [
        cwd / ".mcp.json",
        cwd / ".cursor" / "mcp.json",
        cwd / ".vscode" / "mcp.json",
        Path.home() / ".cursor" / "mcp.json",
        claude_config_path(),
    ]
    return [path for path in candidates if path.is_file()]


def discover_in_directory(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
        for name in filenames:
            if name in _CONFIG_FILENAMES:
                found.append(Path(dirpath) / name)
    return sorted(found)


def collect_paths(raw_paths: list[str]) -> list[Path]:
    if not raw_paths:
        found = default_paths()
        if not found:
            raise CheckError("no MCP config files found")
        return found
    found: list[Path] = []
    missing: list[str] = []
    for raw in raw_paths:
        path = Path(raw)
        if path.is_dir():
            inner = discover_in_directory(path)
            if not inner:
                missing.append(raw)
            found.extend(inner)
        elif path.is_file():
            found.append(path)
        else:
            missing.append(raw)
    if missing:
        raise CheckError("path not found or no MCP config inside: " + ", ".join(missing))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in found:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def load_snapshot(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise CheckError(f"cannot read snapshot {path}: {exc.strerror or exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CheckError(f"snapshot {path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("advisories"), list):
        raise CheckError("snapshot must be an object with an advisories array")
    advisories = data["advisories"]
    if not advisories:
        raise CheckError("snapshot advisories array is empty")
    for advisory in advisories:
        _validate_advisory(advisory)
    return advisories


def _validate_advisory(advisory: Any) -> None:
    if not isinstance(advisory, dict):
        raise CheckError("snapshot advisory must be an object")
    ident = advisory.get("id")
    if not isinstance(ident, str) or not ident.strip():
        raise CheckError("snapshot advisory is missing id")
    kind = advisory.get("kind")
    if kind not in _KINDS:
        raise CheckError(f"{ident} has an unknown kind")
    package = advisory.get("package")
    if not isinstance(package, dict):
        raise CheckError(f"{ident} is missing package")
    name = package.get("name")
    ecosystem = package.get("ecosystem")
    if not isinstance(name, str) or not name.strip():
        raise CheckError(f"{ident} is missing a package name")
    if ecosystem not in _ECOSYSTEMS:
        raise CheckError(f"{ident} ecosystem must be npm or PyPI")
    osv_id = advisory.get("osv_id")
    if osv_id is not None and not isinstance(osv_id, str):
        raise CheckError(f"{ident} osv_id must be a string")
    aliases = advisory.get("aliases", [])
    if aliases is None:
        aliases = []
    if not isinstance(aliases, list) or not all(isinstance(item, str) and item.strip() for item in aliases):
        raise CheckError(f"{ident} aliases must be strings")
    if kind == "malicious-package":
        exact = advisory.get("versions_exact")
        if not isinstance(exact, list) or not exact:
            raise CheckError(f"{ident} is missing versions_exact")
        for item in exact:
            if not isinstance(item, str):
                raise CheckError(f"{ident} versions_exact must be strings")
            parse_version(item)
    else:
        affected = advisory.get("affected")
        if not isinstance(affected, str) or not affected.strip():
            raise CheckError(f"{ident} is missing affected")
        _validate_range(affected, ident)
    fixed = advisory.get("fixed", None)
    if fixed is not None:
        if not isinstance(fixed, str):
            raise CheckError(f"{ident} fixed must be a string or null")
        parse_version(fixed)


def advisory_ids(advisory: dict[str, Any]) -> list[str]:
    ids = [advisory["id"]]
    osv_id = advisory.get("osv_id")
    if isinstance(osv_id, str) and osv_id and osv_id not in ids:
        ids.append(osv_id)
    for alias in advisory.get("aliases") or []:
        if alias not in ids:
            ids.append(alias)
    return ids


def walk_args(args: list[str], takes_value: set[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Split launcher args into ``(flag, value)`` pairs and positionals.

    ``--`` stops flag parsing. A value flag consumes the next token, or the
    text after ``=``.
    """
    options: list[tuple[str, str]] = []
    positionals: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            positionals.extend(args[index + 1 :])
            break
        if arg.startswith("--") and "=" in arg:
            name, value = arg.split("=", 1)
            options.append((name, value))
            index += 1
            continue
        if arg.startswith("-") and arg != "-":
            if arg in takes_value:
                if index + 1 >= len(args):
                    raise CheckError(f"{arg} needs a value")
                options.append((arg, args[index + 1]))
                index += 2
                continue
            options.append((arg, ""))
            index += 1
            continue
        positionals.append(arg)
        index += 1
    return options, positionals


def _pin_from_version(name: str, version: str | None, ecosystem: str, launcher: str) -> dict[str, Any]:
    if version is None or version == "" or version in {"*", "x", "X"}:
        return _package(name, ecosystem, None, "unpinned", launcher)
    if version.lower() == "latest":
        return _package(name, ecosystem, "latest", "latest", launcher)
    if _TAG_RE.fullmatch(version):
        return _package(name, ecosystem, version, "unpinned", launcher)
    parse_version(version)
    return _package(name, ecosystem, version, "pinned", launcher)


def _package(name: str, ecosystem: str, version: str | None, pin: str, launcher: str) -> dict[str, Any]:
    return {
        "name": name,
        "ecosystem": ecosystem,
        "version": version,
        "pin": pin,
        "launcher": launcher,
    }


def parse_npm_spec(spec: str, launcher: str = "npx") -> dict[str, Any]:
    text = spec.strip()
    if text.startswith("npm:"):
        text = text[4:]
    if not text:
        raise CheckError("empty npm package spec")
    if text.startswith("@"):
        body = text[1:]
        slash = body.find("/")
        if slash < 1:
            raise CheckError(f"could not read an npm package name from {spec!r}")
        after = body[slash + 1 :]
        at = after.find("@")
        if at < 0:
            name, version = text, None
        elif at == 0:
            raise CheckError(f"could not read an npm package name from {spec!r}")
        else:
            name = "@" + body[: slash + 1 + at]
            version = after[at + 1 :]
    else:
        at = text.find("@")
        if at < 0:
            name, version = text, None
        elif at == 0:
            raise CheckError(f"could not read an npm package name from {spec!r}")
        else:
            name, version = text[:at], text[at + 1 :]
    if _NPM_NAME_RE.fullmatch(name) is None:
        raise CheckError(f"could not read an npm package name from {spec!r}")
    return _pin_from_version(name, version, "npm", launcher)


def parse_pypi_spec(spec: str, launcher: str) -> dict[str, Any]:
    text = spec.strip()
    if not text:
        raise CheckError("empty PyPI package spec")
    if "://" in text or text.startswith("git+") or re.search(r"\s@\s", text):
        name = re.split(r"\s|@", text, maxsplit=1)[0]
        if _PYPI_SPEC_RE.match(name) is None:
            raise CheckError(f"could not read a package name from {spec!r}")
        return _package(name, "PyPI", None, "unpinned", launcher)
    if "@" in text and "==" not in text and "[" not in text.split("@", 1)[0]:
        name, version = text.split("@", 1)
        if _PYPI_SPEC_RE.match(name) is None:
            raise CheckError(f"could not read a package name from {spec!r}")
        return _pin_from_version(name, version, "PyPI", launcher)
    match = _PYPI_SPEC_RE.match(text)
    if match is None:
        raise CheckError(f"could not read a package name from {spec!r}")
    name = match.group("name")
    rest = re.sub(r"\s*;.*$", "", match.group("rest") or "").strip()
    if rest == "":
        return _package(name, "PyPI", None, "unpinned", launcher)
    constraints = [part.strip() for part in rest.split(",") if part.strip()]
    if len(constraints) != 1:
        return _package(name, "PyPI", rest, "unpinned", launcher)
    operator = _RANGE_OP_RE.match(constraints[0])
    if operator is None:
        raise CheckError(f"could not read a version from {spec!r}")
    op, version = operator.group(1), operator.group(2).strip()
    if op in {"==", "==="} and "*" not in version:
        if version.lower() == "latest":
            return _package(name, "PyPI", "latest", "latest", launcher)
        parse_version(version)
        return _package(name, "PyPI", version, "pinned", launcher)
    return _package(name, "PyPI", version, "unpinned", launcher)


def extract_npx(args: list[str]) -> list[dict[str, Any]]:
    options, positionals = walk_args(args, _NPX_TAKES_VALUE)
    specs = [value for name, value in options if name in {"--package", "-p"}]
    if not specs:
        if not positionals:
            raise CheckError("npx command did not name a package")
        specs = [positionals[0]]
    return [parse_npm_spec(spec, "npx") for spec in specs]


def extract_uvx(args: list[str]) -> list[dict[str, Any]]:
    options, positionals = walk_args(args, _UVX_TAKES_VALUE)
    specs = [value for name, value in options if name in {"--from", "--with", "--with-editable"}]
    if not any(name == "--from" for name, _value in options):
        if not positionals and not specs:
            raise CheckError("uvx command did not name a package")
        if positionals:
            specs.insert(0, positionals[0])
    if not specs:
        raise CheckError("uvx command did not name a package")
    return [parse_pypi_spec(spec, "uvx") for spec in specs]


def extract_pipx(args: list[str]) -> list[dict[str, Any]]:
    options, positionals = walk_args(args, _PIPX_TAKES_VALUE)
    if not positionals:
        raise CheckError("pipx command did not name a package")
    sub = positionals[0]
    if sub not in {"run", "install", "upgrade"}:
        raise NotAPackageLaunch(f"pipx {sub} is not a package launch this check reads")
    spec_opts = [value for name, value in options if name == "--spec"]
    if spec_opts:
        spec = spec_opts[-1]
    elif len(positionals) > 1:
        spec = positionals[1]
    else:
        raise CheckError("pipx command did not name a package")
    return [parse_pypi_spec(spec, "pipx")]


def extract_pip(args: list[str]) -> list[dict[str, Any]]:
    _options, positionals = walk_args(args, _PIP_TAKES_VALUE)
    if not positionals:
        raise CheckError("pip command did not name a package")
    sub = positionals[0]
    if sub not in {"install", "download", "wheel"}:
        raise NotAPackageLaunch(f"pip {sub} does not name a package on the command line")
    packages = [parse_pypi_spec(item, "pip") for item in positionals[1:] if not item.startswith("-")]
    if not packages:
        raise NotAPackageLaunch("pip install did not name a package on the command line")
    return packages


def classify_command(command: str, args: list[str]) -> tuple[str | None, list[str]]:
    base = program_name(command)
    if _PYTHON_RE.fullmatch(base):
        index = 0
        while index < len(args):
            if args[index] == "-m" and index + 1 < len(args) and program_name(args[index + 1]) == "pip":
                return "pip", args[index + 2 :]
            if args[index] in {"-X", "-W", "-c"}:
                index += 2
                continue
            if args[index].startswith("-"):
                index += 1
                continue
            return None, args
        return None, args
    if base == "uv" and len(args) >= 2 and args[0] == "tool" and args[1] == "run":
        return "uvx", args[2:]
    if base in {"npx", "uvx", "pipx", "pip"}:
        return base, args
    return None, args


def extract_launcher(launcher: str, args: list[str]) -> list[dict[str, Any]]:
    if launcher == "npx":
        return extract_npx(args)
    if launcher == "uvx":
        return extract_uvx(args)
    if launcher == "pipx":
        return extract_pipx(args)
    if launcher == "pip":
        return extract_pip(args)
    raise CheckError(f"unknown launcher: {launcher}")


def _is_remote(entry: dict[str, Any]) -> bool:
    return any(key in entry for key in ("url", "uri", "serverUrl", "httpUrl"))


def packages_for_entry(entry: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    """Return extracted packages, or a skip reason when nothing is checked."""
    command = entry.get("command")
    if command is None or command == "":
        if _is_remote(entry):
            return [], "remote url server"
        return [], "no command"
    if not isinstance(command, str):
        raise CheckError("command must be a string")
    args = entry.get("args", [])
    if args is None:
        args = []
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise CheckError("args must be a list of strings")
    launcher, launch_args = classify_command(command, list(args))
    if launcher is None:
        base = program_name(command)
        if base in _CONTAINER_COMMANDS:
            return [], "container launch is not parsed"
        shown = base or command
        return [], f"command {shown} is not npx, uvx, pipx, or pip"
    try:
        return extract_launcher(launcher, launch_args), None
    except NotAPackageLaunch as exc:
        return [], str(exc)


def iter_servers(payload: Any) -> list[tuple[str, dict[str, Any], str]]:
    if not isinstance(payload, dict):
        raise CheckError("config must be a JSON object")
    found: list[tuple[str, dict[str, Any], str]] = []
    seen_key = False
    for key in _SERVER_KEYS:
        if key not in payload:
            continue
        seen_key = True
        block = payload[key]
        if not isinstance(block, dict):
            raise CheckError(f"{key} must be a JSON object")
        for name, entry in block.items():
            if not isinstance(name, str) or not name.strip():
                raise CheckError(f"{key} has a server name that is not a non-empty string")
            if not isinstance(entry, dict):
                raise CheckError(f"{key} entry {name} must be a JSON object")
            found.append((name, entry, key))
    if not seen_key:
        raise CheckError("config has neither mcpServers nor servers")
    return found


def _version_affected(version: str, advisory: dict[str, Any]) -> bool:
    if advisory["kind"] == "malicious-package":
        got = parse_version(version)
        return any(got == parse_version(item) for item in advisory["versions_exact"])
    return version_matches(version, advisory["affected"])


def snapshot_hits(advisories: list[dict[str, Any]], package: dict[str, Any]) -> list[dict[str, Any]]:
    if package["pin"] != "pinned" or not package["version"]:
        return []
    target = normalize_name(package["name"], package["ecosystem"])
    hits: list[dict[str, Any]] = []
    for advisory in advisories:
        info = advisory["package"]
        if info["ecosystem"] != package["ecosystem"]:
            continue
        if normalize_name(info["name"], info["ecosystem"]) != target:
            continue
        if _version_affected(package["version"], advisory):
            hits.append(advisory)
    return hits


def snapshot_name_ids(advisories: list[dict[str, Any]], package: dict[str, Any]) -> list[str]:
    target = normalize_name(package["name"], package["ecosystem"])
    ids: list[str] = []
    for advisory in advisories:
        info = advisory["package"]
        if info["ecosystem"] != package["ecosystem"]:
            continue
        if normalize_name(info["name"], info["ecosystem"]) == target:
            ids.append(advisory["id"])
    return ids


def _fail_message(advisory: dict[str, Any]) -> str:
    shown = _format_ids(advisory_ids(advisory))
    if advisory["kind"] == "malicious-package":
        listed = ", ".join(advisory["versions_exact"])
        return f"{shown} lists {listed} as a malicious package. No fixed version is listed."
    fixed = advisory.get("fixed") or "none"
    return f"{shown} matches affected range {advisory['affected']}. Fixed version: {fixed}."


def _warn_message(package: dict[str, Any], name_ids: list[str]) -> str:
    if package["pin"] == "latest":
        message = "version is @latest"
    elif package["version"]:
        message = "version is not an exact pin"
    else:
        message = "version is not pinned"
    if name_ids:
        message += ". The package name matches bundled advisory " + ", ".join(name_ids)
        message += ", and the version was not checked"
    return message


def osv_identities(vuln: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    ident = vuln.get("id")
    if isinstance(ident, str) and ident:
        ids.append(ident)
    aliases = vuln.get("aliases") or []
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, str) and alias and alias not in ids:
                ids.append(alias)
    return ids


def osv_is_malicious(vuln: dict[str, Any]) -> bool:
    if any(ident.startswith("MAL-") for ident in osv_identities(vuln)):
        return True
    specific = vuln.get("database_specific")
    return isinstance(specific, dict) and "malicious-packages-origins" in specific


def query_osv(name: str, ecosystem: str, version: str, timeout: float = _DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """POST one package version to OSV. Raise CheckError on any unusable answer."""
    parsed = urllib.parse.urlparse(OSV_QUERY_URL)
    if parsed.scheme != "https" or parsed.netloc != "api.osv.dev" or parsed.path != "/v1/query":
        raise CheckError("OSV query host is not api.osv.dev")
    if ecosystem not in _ECOSYSTEMS:
        raise CheckError(f"OSV ecosystem must be npm or PyPI, not {ecosystem!r}")
    sent = version[1:] if len(version) >= 2 and version[0] in "vV" and version[1].isdigit() else version
    vulns: list[dict[str, Any]] = []
    page_token: str | None = None
    for _page in range(_MAX_PAGES):
        body: dict[str, Any] = {
            "package": {"name": name, "ecosystem": ecosystem},
            "version": sent,
        }
        if page_token:
            body["page_token"] = page_token
        request = urllib.request.Request(
            OSV_QUERY_URL,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": f"mcp-config-advisory-check/{__version__}",
            },
            method="POST",
        )
        try:
            with _OPENER.open(request, timeout=timeout) as response:
                raw = response.read(_MAX_BODY + 1)
        except CheckError:
            raise
        except Exception as exc:
            raise CheckError(f"OSV query failed for {name}@{sent}: {exc}") from exc
        if len(raw) > _MAX_BODY:
            raise CheckError(f"OSV response for {name}@{sent} was too large")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CheckError(f"OSV response for {name}@{sent} was not JSON") from exc
        if not isinstance(payload, dict):
            raise CheckError(f"OSV response for {name}@{sent} was not an object")
        batch = payload.get("vulns") or []
        if not isinstance(batch, list):
            raise CheckError(f"OSV response for {name}@{sent} did not list vulns")
        for item in batch:
            if not isinstance(item, dict):
                raise CheckError(f"OSV response for {name}@{sent} had a non-object vuln")
            vulns.append(item)
        token = payload.get("next_page_token")
        if not token:
            return vulns
        if not isinstance(token, str):
            raise CheckError(f"OSV page token for {name}@{sent} was not a string")
        page_token = token
    raise CheckError(f"OSV query for {name}@{sent} did not finish within {_MAX_PAGES} pages")


def check_package(
    advisories: list[dict[str, Any]],
    package: dict[str, Any],
    *,
    offline: bool,
    timeout: float,
) -> tuple[list[dict[str, Any]], str | None]:
    """Return finding fragments for one package and an error message, if any.

    Fragments omit file and server; the caller fills those in.
    """
    if package["pin"] != "pinned":
        name_ids = snapshot_name_ids(advisories, package)
        kind = "latest" if package["pin"] == "latest" else "unpinned"
        return (
            [
                {
                    "severity": "WARN",
                    "kind": kind,
                    "advisory_id": name_ids[0] if name_ids else None,
                    "advisory_ids": name_ids,
                    "source": "config",
                    "message": _warn_message(package, name_ids),
                    **{key: package[key] for key in ("launcher", "ecosystem", "version", "pin")},
                    "package": package["name"],
                }
            ],
            None,
        )
    findings: list[dict[str, Any]] = []
    for advisory in snapshot_hits(advisories, package):
        ids = advisory_ids(advisory)
        findings.append(
            {
                "severity": "FAIL",
                "kind": advisory["kind"],
                "advisory_id": advisory["id"],
                "advisory_ids": ids,
                "source": "snapshot",
                "message": _fail_message(advisory),
                "launcher": package["launcher"],
                "ecosystem": package["ecosystem"],
                "package": package["name"],
                "version": package["version"],
                "pin": package["pin"],
            }
        )
    if offline:
        return findings, None
    try:
        vulns = query_osv(package["name"], package["ecosystem"], package["version"], timeout=timeout)
    except CheckError as exc:
        return findings, str(exc)
    for vuln in vulns:
        ids = osv_identities(vuln)
        if not ids:
            ids = ["OSV"]
        merged = False
        for finding in findings:
            if set(ids) & set(finding["advisory_ids"]):
                for ident in ids:
                    if ident not in finding["advisory_ids"]:
                        finding["advisory_ids"].append(ident)
                merged = True
                break
        if merged:
            continue
        malicious = osv_is_malicious(vuln)
        primary = ids[0]
        if malicious:
            message = f"OSV {primary} reports this version as a malicious package."
            kind = "malicious-package"
        else:
            message = f"OSV {primary} reports this version as affected."
            kind = "vulnerable-version"
        findings.append(
            {
                "severity": "FAIL",
                "kind": kind,
                "advisory_id": primary,
                "advisory_ids": ids,
                "source": "osv",
                "message": message,
                "launcher": package["launcher"],
                "ecosystem": package["ecosystem"],
                "package": package["name"],
                "version": package["version"],
                "pin": package["pin"],
            }
        )
    return findings, None


def load_config(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise CheckError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CheckError(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc


def check_paths(
    paths: list[Path],
    advisories: list[dict[str, Any]],
    *,
    offline: bool,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    checked = 0
    for path in paths:
        shown = display_path(path)
        try:
            payload = load_config(path)
            servers = iter_servers(payload)
        except CheckError as exc:
            errors.append({"file": shown, "server": None, "message": str(exc)})
            continue
        for server, entry, config_key in servers:
            try:
                packages, reason = packages_for_entry(entry)
            except CheckError as exc:
                errors.append({"file": shown, "server": server, "message": str(exc)})
                continue
            if reason is not None:
                skipped.append({"file": shown, "server": server, "reason": reason})
                continue
            for package in packages:
                checked += 1
                try:
                    package_findings, problem = check_package(
                        advisories,
                        package,
                        offline=offline,
                        timeout=timeout,
                    )
                except CheckError as exc:
                    errors.append({"file": shown, "server": server, "message": str(exc)})
                    continue
                for finding in package_findings:
                    finding["file"] = shown
                    finding["server"] = server
                    finding["config_key"] = config_key
                    findings.append(finding)
                if problem:
                    errors.append({"file": shown, "server": server, "message": problem})
    fail_count = sum(1 for finding in findings if finding["severity"] == "FAIL")
    warn_count = sum(1 for finding in findings if finding["severity"] == "WARN")
    exit_code = EXIT_ERROR if errors else EXIT_FINDINGS if fail_count else EXIT_OK
    return {
        "tool": "mcp-config-advisory-check",
        "version": __version__,
        "offline": offline,
        "ok": exit_code == EXIT_OK,
        "exit_code": exit_code,
        "summary": {
            "checked": checked,
            "fail": fail_count,
            "warn": warn_count,
            "skip": len(skipped),
            "error": len(errors),
        },
        "findings": findings,
        "skipped": skipped,
        "errors": errors,
    }


def _format_ids(ids: list[str]) -> str:
    if not ids:
        return ""
    if len(ids) == 1:
        return ids[0]
    return ids[0] + " (" + ", ".join(ids[1:]) + ")"


def format_coordinate(finding: dict[str, Any]) -> str:
    name = finding["package"]
    version = finding.get("version")
    pin = finding.get("pin")
    if pin == "latest":
        return f"{name}@latest"
    if version and pin == "pinned":
        if finding["ecosystem"] == "npm":
            return f"{name}@{version}"
        return f"{name}=={version}"
    return name


def render_text(result: dict[str, Any]) -> str:
    lines = [
        "MCP config advisory check",
        "mode: " + ("offline" if result["offline"] else "online"),
        "",
    ]
    by_file: dict[str, list[dict[str, Any]]] = {}
    for finding in result["findings"]:
        by_file.setdefault(finding["file"], []).append(finding)
    for path, items in by_file.items():
        lines.append(path)
        for item in items:
            ident = ""
            if item["severity"] == "FAIL" and item.get("advisory_ids"):
                ident = "  " + _format_ids(item["advisory_ids"])
            lines.append(
                f"  {item['severity']}  {item['kind']}{ident}  {item['server']}  {format_coordinate(item)}"
            )
            lines.append(f"        {item['message']}")
        lines.append("")
    if result["skipped"]:
        lines.append("skipped:")
        for item in result["skipped"]:
            lines.append(f"  {item['file']}  {item['server']}  {item['reason']}")
        lines.append("")
    if result["errors"]:
        lines.append("errors:")
        for item in result["errors"]:
            where = item.get("file") or "snapshot"
            server = item.get("server")
            prefix = f"{where}  {server}  " if server else f"{where}  "
            lines.append(f"  {prefix}{item['message']}")
        lines.append("")
    summary = result["summary"]
    lines.append(
        "summary: checked={checked} fail={fail} warn={warn} skip={skip} error={error}".format(**summary)
    )
    return "\n".join(lines) + "\n"


def render_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def _error_result(message: str, offline: bool) -> dict[str, Any]:
    return {
        "tool": "mcp-config-advisory-check",
        "version": __version__,
        "offline": offline,
        "ok": False,
        "exit_code": EXIT_ERROR,
        "summary": {"checked": 0, "fail": 0, "warn": 0, "skip": 0, "error": 1},
        "findings": [],
        "skipped": [],
        "errors": [{"file": None, "server": None, "message": message}],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp_config_advisory_check.py",
        description=(
            "Check MCP client configs for package versions covered by the bundled "
            "advisory snapshot and, unless --offline, the OSV query API. "
            "Read-only. The standard library is enough. "
            "Use it on configs you own or are explicitly allowed to assess."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help=(
            "Config files or directories. A directory is searched for .mcp.json, "
            "mcp.json, and claude_desktop_config.json. With no path, look for the "
            "project files, ~/.cursor/mcp.json, and the Claude Desktop config."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not contact OSV. Check the bundled snapshot only.",
    )
    parser.add_argument("--json", action="store_true", help="Print the result as JSON.")
    parser.add_argument(
        "--snapshot",
        help="Advisory snapshot JSON. Defaults to advisory_snapshot.json beside this script.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=_DEFAULT_TIMEOUT,
        help=f"Seconds to wait for each OSV query (default {_DEFAULT_TIMEOUT:g}).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        result = _error_result("--timeout must be greater than 0", args.offline)
        sys.stdout.write(render_json(result) if args.json else render_text(result))
        return EXIT_ERROR
    snapshot_path = Path(args.snapshot) if args.snapshot else DEFAULT_SNAPSHOT
    try:
        advisories = load_snapshot(snapshot_path)
        paths = collect_paths(args.paths)
    except CheckError as exc:
        result = _error_result(str(exc), args.offline)
        sys.stdout.write(render_json(result) if args.json else render_text(result))
        return EXIT_ERROR
    result = check_paths(paths, advisories, offline=args.offline, timeout=args.timeout)
    sys.stdout.write(render_json(result) if args.json else render_text(result))
    return int(result["exit_code"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(EXIT_OK)
