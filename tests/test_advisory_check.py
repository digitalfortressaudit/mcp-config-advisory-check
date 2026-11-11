#!/usr/bin/env python3
"""Unit tests for the MCP config advisory check. No network."""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import mcp_config_advisory_check as check  # noqa: E402

EXAMPLES = ROOT / "examples"
SNAPSHOT_IDS = (
    "GHSA-rvw8-22w3-342v",
    "GHSA-w766-5x43-whvw",
    "GHSA-r6mm-377j-qg8m",
    "AWS-2026-152",
)


def _joined(chars: list[str]) -> str:
    return "".join(chars)


class _Body:
    def __init__(self, payload: dict) -> None:
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self, _limit: int = -1) -> bytes:
        return self._raw

    def __enter__(self) -> _Body:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class AdvisoryCheckTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = check.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _write(self, directory: Path, name: str, payload: object) -> Path:
        path = directory / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _config(self, servers: dict, key: str = "mcpServers") -> dict:
        return {key: servers}

    def _entry(self, command: str, args: list[str]) -> dict:
        return {"command": command, "args": args}

    def test_snapshot_is_the_four_verified_records(self) -> None:
        advisories = check.load_snapshot(check.DEFAULT_SNAPSHOT)
        self.assertEqual([item["id"] for item in advisories], list(SNAPSHOT_IDS))
        by_id = {item["id"]: item for item in advisories}
        npm = by_id["GHSA-rvw8-22w3-342v"]
        self.assertEqual(npm["osv_id"], "MAL-2026-18486")
        self.assertEqual(npm["kind"], "malicious-package")
        self.assertEqual(npm["package"], {"name": "@ifasn/md-doc-mcp", "ecosystem": "npm"})
        self.assertEqual(npm["versions_exact"], ["1.0.3", "1.0.4", "1.0.5"])
        self.assertIsNone(npm["fixed"])
        git = by_id["GHSA-w766-5x43-whvw"]
        self.assertEqual(git["package"]["name"], "mcp-server-git")
        self.assertEqual(git["package"]["ecosystem"], "PyPI")
        self.assertEqual(git["affected"], "< 2026.10.28")
        self.assertEqual(git["fixed"], "2026.10.28")
        serverless = by_id["GHSA-r6mm-377j-qg8m"]
        self.assertEqual(serverless["package"]["name"], "awslabs.aws-serverless-mcp-server")
        self.assertEqual(serverless["affected"], "< 0.2.1")
        self.assertEqual(serverless["fixed"], "0.2.1")
        aws = by_id["AWS-2026-152"]
        self.assertEqual(aws["aliases"], ["GHSA-4prq-p2x5-w9fh", "CVE-2026-115413"])
        self.assertEqual(aws["package"]["name"], "awslabs.aws-api-mcp-server")
        self.assertEqual(aws["affected"], ">=1.3.0,<1.6.0")
        self.assertEqual(aws["fixed"], "1.6.0")

    def test_version_order_and_ranges(self) -> None:
        self.assertEqual(check.parse_version("1.0"), check.parse_version("1.0.0"))
        self.assertEqual(check.parse_version("v1.0.4"), check.parse_version("1.0.4"))
        self.assertLess(check.parse_version("1.0.0a1"), check.parse_version("1.0.0"))
        self.assertLess(check.parse_version("2026.10.19"), check.parse_version("2026.10.28"))
        self.assertLess(check.parse_version("2026.9.30"), check.parse_version("2026.10.28"))
        self.assertFalse(check.version_matches("2026.10.28", "< 2026.10.28"))
        self.assertTrue(check.version_matches("2026.10.27", "< 2026.10.28"))
        self.assertTrue(check.version_matches("2026.9.30", "< 2026.10.28"))
        self.assertFalse(check.version_matches("0.2.1", "< 0.2.1"))
        self.assertTrue(check.version_matches("0.2.0", "< 0.2.1"))
        self.assertFalse(check.version_matches("0.10.0", "< 0.2.1"))
        self.assertTrue(check.version_matches("1.3.0", ">=1.3.0,<1.6.0"))
        self.assertTrue(check.version_matches("1.5.9", ">=1.3.0,<1.6.0"))
        self.assertFalse(check.version_matches("1.2.9", ">=1.3.0,<1.6.0"))
        self.assertFalse(check.version_matches("1.6.0", ">=1.3.0,<1.6.0"))
        self.assertFalse(check.version_matches("1.10.0", ">=1.3.0,<1.6.0"))
        self.assertTrue(check.version_matches("1.4.5", "~=1.4.0"))
        self.assertFalse(check.version_matches("1.5.0", "~=1.4.0"))

    def test_launchers_extract_package_and_version(self) -> None:
        cases = [
            ("npx", ["-y", "@example/notes-mcp@1.4.2"], "npm", "@example/notes-mcp", "1.4.2", "pinned"),
            ("npx", ["-y", "@scope/pkg"], "npm", "@scope/pkg", None, "unpinned"),
            ("npx", ["-y", "@scope/pkg@latest"], "npm", "@scope/pkg", "latest", "latest"),
            ("npx", ["-y", "-p", "@scope/pkg@1.2.3", "tool"], "npm", "@scope/pkg", "1.2.3", "pinned"),
            ("/usr/local/bin/npx", ["--yes", "notes@2.0.0", "/tmp"], "npm", "notes", "2.0.0", "pinned"),
            ("npx.cmd", ["-y", "notes@2.0.0"], "npm", "notes", "2.0.0", "pinned"),
            ("uvx", ["example-fetch-mcp==0.9.1"], "PyPI", "example-fetch-mcp", "0.9.1", "pinned"),
            ("uvx", ["example-fetch-mcp"], "PyPI", "example-fetch-mcp", None, "unpinned"),
            ("uvx", ["--from", "demo-pkg==1.2.3", "demo-pkg"], "PyPI", "demo-pkg", "1.2.3", "pinned"),
            ("uv", ["tool", "run", "demo-pkg==4.5.6"], "PyPI", "demo-pkg", "4.5.6", "pinned"),
            ("pipx", ["run", "example-docs-mcp==2.0.0"], "PyPI", "example-docs-mcp", "2.0.0", "pinned"),
            ("pipx", ["run", "--spec", "example-docs-mcp==2.0.0", "docs"], "PyPI", "example-docs-mcp", "2.0.0", "pinned"),
            ("pip", ["install", "example-helper-mcp==3.1.0"], "PyPI", "example-helper-mcp", "3.1.0", "pinned"),
            ("python", ["-m", "pip", "install", "example-helper-mcp==3.1.0"], "PyPI", "example-helper-mcp", "3.1.0", "pinned"),
            ("python3", ["-m", "pip", "install", "demo>=1.0"], "PyPI", "demo", "1.0", "unpinned"),
        ]
        for command, args, ecosystem, name, version, pin in cases:
            with self.subTest(command=command, args=args):
                packages, reason = check.packages_for_entry(self._entry(command, args))
                self.assertIsNone(reason)
                self.assertEqual(len(packages), 1)
                got = packages[0]
                self.assertEqual(got["ecosystem"], ecosystem)
                self.assertEqual(got["name"], name)
                self.assertEqual(got["version"], version)
                self.assertEqual(got["pin"], pin)

    def test_mcp_servers_and_servers_keys(self) -> None:
        entry = self._entry("npx", ["-y", "@example/notes-mcp@1.4.2"])
        for key in ("mcpServers", "servers"):
            with self.subTest(key=key):
                servers = check.iter_servers(self._config({"notes": entry}, key=key))
                self.assertEqual(len(servers), 1)
                name, payload, found_key = servers[0]
                self.assertEqual((name, found_key), ("notes", key))
                packages, reason = check.packages_for_entry(payload)
                self.assertIsNone(reason)
                self.assertEqual(packages[0]["name"], "@example/notes-mcp")
        both = {
            "mcpServers": {"left": self._entry("npx", ["-y", "left@1.0.0"])},
            "servers": {"right": self._entry("uvx", ["right==2.0.0"])},
        }
        names = [item[0] for item in check.iter_servers(both)]
        self.assertEqual(names, ["left", "right"])

    def test_remote_and_container_are_skipped(self) -> None:
        remote, remote_reason = check.packages_for_entry({"type": "http", "url": "https://mcp.example.invalid/mcp"})
        self.assertEqual(remote, [])
        self.assertEqual(remote_reason, "remote url server")
        docker, docker_reason = check.packages_for_entry(self._entry("docker", ["run", "ghcr.io/example/mcp:1"]))
        self.assertEqual(docker, [])
        self.assertEqual(docker_reason, "container launch is not parsed")
        other, other_reason = check.packages_for_entry(self._entry("node", ["server.js"]))
        self.assertEqual(other, [])
        self.assertIn("not npx, uvx, pipx, or pip", other_reason or "")

    def test_each_snapshot_advisory_fails_and_fixed_versions_do_not(self) -> None:
        advisories = check.load_snapshot(check.DEFAULT_SNAPSHOT)
        cases = [
            ("npx", ["-y", "@ifasn/md-doc-mcp@1.0.3"], "GHSA-rvw8-22w3-342v", True),
            ("npx", ["-y", "@ifasn/md-doc-mcp@1.0.4"], "GHSA-rvw8-22w3-342v", True),
            ("npx", ["-y", "@IFASN/md-doc-mcp@1.0.5"], "GHSA-rvw8-22w3-342v", True),
            ("npx", ["-y", "@ifasn/md-doc-mcp@1.0.2"], "GHSA-rvw8-22w3-342v", False),
            ("npx", ["-y", "@ifasn/md-doc-mcp@1.0.6"], "GHSA-rvw8-22w3-342v", False),
            ("npx", ["-y", "@ifasn/md-doc-mcp@1.0.30"], "GHSA-rvw8-22w3-342v", False),
            ("uvx", ["mcp-server-git==2026.10.19"], "GHSA-w766-5x43-whvw", True),
            ("uvx", ["Mcp_Server.Git==2026.9.30"], "GHSA-w766-5x43-whvw", True),
            ("uvx", ["mcp-server-git==2026.10.28"], "GHSA-w766-5x43-whvw", False),
            ("pipx", ["run", "awslabs.aws-serverless-mcp-server==0.2.0"], "GHSA-r6mm-377j-qg8m", True),
            ("pipx", ["run", "awslabs.aws-serverless-mcp-server==0.10.0"], "GHSA-r6mm-377j-qg8m", False),
            ("pipx", ["run", "awslabs.aws-serverless-mcp-server==0.2.1"], "GHSA-r6mm-377j-qg8m", False),
            ("pip", ["install", "awslabs.aws-api-mcp-server==1.3.0"], "AWS-2026-152", True),
            ("pip", ["install", "awslabs.aws-api-mcp-server==1.5.0"], "AWS-2026-152", True),
            ("pip", ["install", "awslabs.aws-api-mcp-server==1.5.9"], "AWS-2026-152", True),
            ("pip", ["install", "awslabs.aws-api-mcp-server==1.2.9"], "AWS-2026-152", False),
            ("pip", ["install", "awslabs.aws-api-mcp-server==1.6.0"], "AWS-2026-152", False),
            ("pip", ["install", "awslabs.aws-api-mcp-server==1.10.0"], "AWS-2026-152", False),
        ]
        for command, args, advisory_id, expect_fail in cases:
            with self.subTest(args=args):
                packages, reason = check.packages_for_entry(self._entry(command, args))
                self.assertIsNone(reason)
                hits = check.snapshot_hits(advisories, packages[0])
                ids = [item["id"] for item in hits]
                if expect_fail:
                    self.assertEqual(ids, [advisory_id])
                else:
                    self.assertEqual(ids, [])

    def test_unpinned_warns_and_exits_0(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                Path(tmp),
                "mcp.json",
                self._config(
                    {
                        "floating": self._entry("uvx", ["example-fetch-mcp"]),
                        "moving": self._entry("npx", ["-y", "@example/docs-mcp@latest"]),
                        "named": self._entry("uvx", ["mcp-server-git"]),
                    }
                ),
            )
            code, out, err = self._run(["--offline", "--json", str(path)])
            self.assertEqual(err, "")
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["summary"]["fail"], 0)
            self.assertEqual(payload["summary"]["warn"], 3)
            by_server = {item["server"]: item for item in payload["findings"]}
            self.assertEqual(by_server["floating"]["kind"], "unpinned")
            self.assertIn("not pinned", by_server["floating"]["message"])
            self.assertEqual(by_server["moving"]["kind"], "latest")
            self.assertIn("@latest", by_server["moving"]["message"])
            self.assertEqual(by_server["named"]["severity"], "WARN")
            self.assertIn("GHSA-w766-5x43-whvw", by_server["named"]["message"])
            self.assertNotEqual(by_server["named"]["severity"], "FAIL")

    def test_offline_examples_and_no_network(self) -> None:
        def explode(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("network used")

        with mock.patch.object(check._OPENER, "open", explode):
            clean_code, clean_out, clean_err = self._run(["--offline", str(EXAMPLES / "clean")])
            risky_code, risky_out, risky_err = self._run(["--offline", str(EXAMPLES / "risky")])
        self.assertEqual(clean_err, "")
        self.assertEqual(risky_err, "")
        self.assertEqual(clean_code, 0)
        self.assertNotIn("FAIL", clean_out)
        self.assertNotIn("WARN", clean_out)
        self.assertIn("skip=1", clean_out)
        self.assertEqual(risky_code, 1)
        self.assertGreaterEqual(risky_out.count("\n  FAIL"), 4)
        for advisory_id in SNAPSHOT_IDS:
            lines = [line for line in risky_out.splitlines() if advisory_id in line and "FAIL" in line]
            self.assertTrue(lines, advisory_id)
        self.assertIn("WARN  unpinned", risky_out)
        self.assertIn("WARN  latest", risky_out)
        self.assertIn("@latest", risky_out)
        self.assertIn("version is not pinned", risky_out)

    def test_examples_match_acceptance_commands(self) -> None:
        script = ROOT / "mcp_config_advisory_check.py"
        clean = subprocess.run(
            [sys.executable, str(script), "--offline", str(EXAMPLES / "clean")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        risky = subprocess.run(
            [sys.executable, str(script), "--offline", str(EXAMPLES / "risky")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertEqual(risky.returncode, 1, risky.stderr)
        self.assertEqual(clean.stderr, "")
        self.assertEqual(risky.stderr, "")
        for advisory_id in (*SNAPSHOT_IDS, "GHSA-4prq-p2x5-w9fh"):
            self.assertIn(advisory_id, risky.stdout)
        self.assertIn("WARN", risky.stdout)

    def test_json_output(self) -> None:
        code, out, err = self._run(["--offline", "--json", str(EXAMPLES / "risky")])
        self.assertEqual(err, "")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertTrue(payload["offline"])
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["summary"]["fail"], 4)
        self.assertEqual(payload["summary"]["warn"], 2)
        kinds = {(item["severity"], item["advisory_id"], item["package"]) for item in payload["findings"]}
        self.assertIn(("FAIL", "GHSA-rvw8-22w3-342v", "@ifasn/md-doc-mcp"), kinds)
        self.assertIn(("FAIL", "GHSA-w766-5x43-whvw", "mcp-server-git"), kinds)
        self.assertIn(("FAIL", "GHSA-r6mm-377j-qg8m", "awslabs.aws-serverless-mcp-server"), kinds)
        self.assertIn(("FAIL", "AWS-2026-152", "awslabs.aws-api-mcp-server"), kinds)
        self.assertIn(("WARN", None, "@example/notes-mcp"), kinds)
        self.assertIn(("WARN", None, "@example/docs-mcp"), kinds)
        servers = {item["config_key"] for item in payload["findings"]}
        self.assertEqual(servers, {"mcpServers"})
        clean_code, clean_out, _clean_err = self._run(["--offline", "--json", str(EXAMPLES / "clean")])
        self.assertEqual(clean_code, 0)
        clean_payload = json.loads(clean_out)
        self.assertTrue(clean_payload["ok"])
        self.assertEqual(clean_payload["findings"], [])
        self.assertEqual(clean_payload["summary"]["checked"], 4)
        self.assertEqual(clean_payload["skipped"][0]["reason"], "remote url server")
        vscode = EXAMPLES / "clean" / ".vscode" / "mcp.json"
        code_vs, out_vs, _err_vs = self._run(["--offline", "--json", str(vscode)])
        self.assertEqual(code_vs, 0)
        vs_payload = json.loads(out_vs)
        self.assertEqual(vs_payload["summary"]["checked"], 1)
        self.assertEqual(vs_payload["skipped"][0]["server"], "remote-demo")

    def test_directory_discovery_ignores_unrelated_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.json").write_text("{}", encoding="utf-8")
            git_dir = root / ".git"
            git_dir.mkdir()
            (git_dir / "mcp.json").write_text("{}", encoding="utf-8")
            self._write(root, ".mcp.json", self._config({"notes": self._entry("npx", ["-y", "notes@1.0.0"])}))
            (root / ".vscode").mkdir()
            self._write(
                root / ".vscode",
                "mcp.json",
                self._config({"docs": self._entry("pipx", ["run", "docs==2.0.0"])}, key="servers"),
            )
            code, out, err = self._run(["--offline", "--json", str(root)])
            self.assertEqual((code, err), (0, ""))
            payload = json.loads(out)
            self.assertEqual(payload["summary"]["checked"], 2)
            self.assertEqual(payload["summary"]["error"], 0)

    def test_parse_and_snapshot_errors_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "bad.json"
            bad.write_text("{", encoding="utf-8")
            code, out, _err = self._run(["--offline", str(bad)])
            self.assertEqual(code, 2)
            self.assertIn("not valid JSON", out)
            missing_code, missing_out, _missing_err = self._run(["--offline", str(root / "missing.json")])
            self.assertEqual(missing_code, 2)
            self.assertIn("path not found", missing_out)
            empty = root / "empty"
            empty.mkdir()
            empty_code, empty_out, _empty_err = self._run(["--offline", str(empty)])
            self.assertEqual(empty_code, 2)
            self.assertIn("no MCP config", empty_out)
            broken = root / "servers.json"
            broken.write_text(json.dumps({"servers": []}), encoding="utf-8")
            broken_code, broken_out, _broken_err = self._run(["--offline", str(broken)])
            self.assertEqual(broken_code, 2)
            self.assertIn("servers must be a JSON object", broken_out)
            args_bad = self._write(root, "args.json", self._config({"notes": {"command": "npx", "args": [1]}}))
            args_code, args_out, _args_err = self._run(["--offline", str(args_bad)])
            self.assertEqual(args_code, 2)
            self.assertIn("args must be a list of strings", args_out)
        code_snap, out_snap, _err_snap = self._run(["--offline", "--snapshot", str(ROOT / "missing-snapshot.json"), str(EXAMPLES / "clean")])
        self.assertEqual(code_snap, 2)
        self.assertIn("cannot read snapshot", out_snap)

    def test_online_merges_osv_and_keeps_snapshot(self) -> None:
        calls: list[dict] = []

        def fake_open(request: object, timeout: float = 20.0) -> _Body:
            self.assertGreater(timeout, 0)
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            self.assertEqual(request.full_url, "https://api.osv.dev/v1/query")  # type: ignore[attr-defined]
            self.assertEqual(request.get_method(), "POST")  # type: ignore[attr-defined]
            calls.append(body)
            name = body["package"]["name"]
            if name == "@example/other-mcp":
                return _Body(
                    {
                        "vulns": [
                            {
                                "id": "MAL-2099-1",
                                "database_specific": {"malicious-packages-origins": [{"source": "test"}]},
                            }
                        ]
                    }
                )
            if name == "example-plain":
                return _Body({"vulns": [{"id": "GHSA-test-test-test", "aliases": ["CVE-2099-1"]}]})
            if name == "@ifasn/md-doc-mcp":
                return _Body({"vulns": [{"id": "MAL-2026-18486"}], "next_page_token": "page-2"})
            return _Body({})

        pages = {"@ifasn/md-doc-mcp": 0}

        def paged_open(request: object, timeout: float = 20.0) -> _Body:
            body = json.loads(request.data.decode("utf-8"))  # type: ignore[attr-defined]
            if body["package"]["name"] == "@ifasn/md-doc-mcp":
                pages["@ifasn/md-doc-mcp"] += 1
                if body.get("page_token") == "page-2":
                    return _Body({"vulns": []})
                return fake_open(request, timeout)
            return fake_open(request, timeout)

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                Path(tmp),
                "mcp.json",
                self._config(
                    {
                        "markdown": self._entry("npx", ["-y", "@ifasn/md-doc-mcp@1.0.4"]),
                        "git": self._entry("uvx", ["mcp-server-git==2026.10.19"]),
                        "other": self._entry("npx", ["-y", "@example/other-mcp@1.2.3"]),
                        "plain": self._entry("uvx", ["example-plain==1.0.0"]),
                        "safe": self._entry("uvx", ["example-fetch-mcp==0.9.1"]),
                    }
                ),
            )
            with mock.patch.object(check._OPENER, "open", paged_open):
                code, out, err = self._run(["--json", str(path)])
        self.assertEqual(err, "")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertFalse(payload["offline"])
        queried = {(item["package"]["name"], item["package"]["ecosystem"], item["version"]) for item in calls}
        self.assertIn(("@ifasn/md-doc-mcp", "npm", "1.0.4"), queried)
        self.assertIn(("mcp-server-git", "PyPI", "2026.10.19"), queried)
        self.assertIn(("@example/other-mcp", "npm", "1.2.3"), queried)
        self.assertIn(("example-plain", "PyPI", "1.0.0"), queried)
        self.assertIn(("example-fetch-mcp", "PyPI", "0.9.1"), queried)
        self.assertGreaterEqual(pages["@ifasn/md-doc-mcp"], 2)
        by_package: dict[str, list[dict]] = {}
        for finding in payload["findings"]:
            by_package.setdefault(finding["package"], []).append(finding)
        malware = by_package["@ifasn/md-doc-mcp"]
        self.assertEqual(len(malware), 1)
        self.assertEqual(malware[0]["source"], "snapshot")
        self.assertIn("MAL-2026-18486", malware[0]["advisory_ids"])
        self.assertEqual(by_package["mcp-server-git"][0]["advisory_id"], "GHSA-w766-5x43-whvw")
        self.assertEqual(by_package["@example/other-mcp"][0]["kind"], "malicious-package")
        self.assertEqual(by_package["@example/other-mcp"][0]["source"], "osv")
        self.assertEqual(by_package["example-plain"][0]["kind"], "vulnerable-version")
        self.assertIn("CVE-2099-1", by_package["example-plain"][0]["advisory_ids"])
        self.assertNotIn("example-fetch-mcp", by_package)

    def test_online_network_error_exits_2_and_keeps_snapshot_fail(self) -> None:
        def fake_open(*_args: object, **_kwargs: object) -> None:
            raise urllib.error.URLError("blocked")

        with mock.patch.object(check._OPENER, "open", fake_open):
            code, out, err = self._run(["--json", str(EXAMPLES / "risky")])
        self.assertEqual(err, "")
        self.assertEqual(code, 2)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertGreaterEqual(payload["summary"]["fail"], 4)
        self.assertGreaterEqual(payload["summary"]["error"], 1)
        self.assertTrue(any("OSV query failed" in item["message"] for item in payload["errors"]))
        ids = {item["advisory_id"] for item in payload["findings"] if item["severity"] == "FAIL"}
        self.assertTrue(set(SNAPSHOT_IDS) <= ids)

    def test_osv_malicious_marker_without_mal_prefix(self) -> None:
        def fake_open(*_args: object, **_kwargs: object) -> _Body:
            return _Body(
                {
                    "vulns": [
                        {
                            "id": "GHSA-mark-mark-mark",
                            "database_specific": {"malicious-packages-origins": [{"source": "test"}]},
                        }
                    ]
                }
            )

        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(Path(tmp), "mcp.json", self._config({"notes": self._entry("npx", ["-y", "notes@1.2.3"])}))
            with mock.patch.object(check._OPENER, "open", fake_open):
                code, out, _err = self._run(["--json", str(path)])
        self.assertEqual(code, 1)
        finding = json.loads(out)["findings"][0]
        self.assertEqual(finding["kind"], "malicious-package")
        self.assertEqual(finding["source"], "osv")

    def test_claude_config_paths(self) -> None:
        home = Path("/home/tester")
        with mock.patch.object(check.Path, "home", return_value=home):
            with mock.patch("sys.platform", "darwin"):
                self.assertEqual(
                    check.claude_config_path(),
                    home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
                )
            with mock.patch("sys.platform", "win32"):
                with mock.patch.dict(os.environ, {"APPDATA": r"C:\Users\tester\AppData\Roaming"}):
                    self.assertEqual(
                        check.claude_config_path(),
                        Path(r"C:\Users\tester\AppData\Roaming") / "Claude" / "claude_desktop_config.json",
                    )
            with mock.patch("sys.platform", "linux"):
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("XDG_CONFIG_HOME", None)
                    self.assertEqual(
                        check.claude_config_path(),
                        home / ".config" / "Claude" / "claude_desktop_config.json",
                    )
                with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "/tmp/xdg-config"}):
                    self.assertEqual(
                        check.claude_config_path(),
                        Path("/tmp/xdg-config") / "Claude" / "claude_desktop_config.json",
                    )

    def test_readme_links_footer_and_wording(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        before, marker, after = readme.partition("## Full pack")
        self.assertEqual(marker, "## Full pack")
        self.assertNotIn("gumroad.com", before.lower())
        section, _sep, rest = after.partition("\n## ")
        self.assertEqual(section.count("gumroad.com"), 2)
        self.assertNotIn("gumroad.com", rest.lower())
        self.assertIn(
            "**[$79 MCP & Multi-Agent Authorization Security Pack: Trust, Delegation & Audit Evidence](https://fortressaudit.gumroad.com/l/wphmlq?utm_source=github&utm_medium=repo&utm_campaign=mcp-config-advisory-check)**",
            section,
        )
        self.assertIn(
            "**[$99 AI Security & Infrastructure Prompt Pack: LLM Agents, MCP, Kubernetes & Cloud Audits](https://fortressaudit.gumroad.com/l/myyeen?utm_source=github&utm_medium=repo&utm_campaign=mcp-config-advisory-check)**",
            section,
        )
        self.assertTrue(readme.rstrip().endswith("© 2026 Digital Fortress · github.com/digitalfortressaudit"))
        banned = [
            _joined(["r", "e", "v", "i", "e", "w"]),
            _joined(["r", "o", "u", "n", "d"]),
            _joined(["l", "e", "v", "e", "r", "l", "a", "r", "k"]),
            _joined(["d", "a", "n", "i", "e", "l"]),
        ]
        short_name = re.compile(r"\b" + _joined(["d", "a", "n"]) + r"\b", re.IGNORECASE)
        for path in ROOT.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in {".py", ".md", ".json"} and path.name != "LICENSE":
                continue
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            for token in banned:
                self.assertNotIn(token, lowered, str(path.relative_to(ROOT)))
            self.assertIsNone(short_name.search(text), str(path.relative_to(ROOT)))

    def test_script_imports_stdlib_only(self) -> None:
        tree = ast.parse((ROOT / "mcp_config_advisory_check.py").read_text(encoding="utf-8"))
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        allowed = {"__future__", "argparse", "functools", "json", "os", "pathlib", "re", "sys", "typing", "urllib"}
        self.assertTrue(modules <= allowed, modules - allowed)
        source = (ROOT / "mcp_config_advisory_check.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("os.system", source)


if __name__ == "__main__":
    unittest.main()
