# MCP Config Advisory Check: malicious and vulnerable MCP server packages in Cursor, VS Code and Claude Desktop configs

Read local MCP client config files and flag package launches that match a known advisory. One read-only Python script. The standard library is enough.

Use it on configs and machines you own or are explicitly allowed to assess.

## Why it matters

An MCP client config names the program that starts each server. That program is often `npx`, `uvx`, `pipx`, or `pip`, with a package name and sometimes a version. A pinned version can still be a known-malicious release, or a release older than the fixed version in a public advisory. This checker reads the config text you point it at. It does not install the package.

Two inputs are combined when you are online: a query to the [OSV](https://osv.dev/) API, and a small snapshot shipped with this script. As of 2026-11-09 the snapshot is what covers three PyPI advisories that OSV did not return for those packages. Offline mode uses the snapshot only.

## Quickstart

Requires Python 3.9 or newer.

From this directory:

```bash
python3 mcp_config_advisory_check.py --offline examples/clean
python3 mcp_config_advisory_check.py --offline examples/risky
python3 mcp_config_advisory_check.py --offline --json examples/risky
```

`examples/clean` is a pair of fictional configs. The package names are pinned and are not in the snapshot. One server is a remote `url` and is skipped. That command exits `0`:

```text
MCP config advisory check
mode: offline

skipped:
  examples/clean/.vscode/mcp.json  remote-demo  remote url server

summary: checked=4 fail=0 warn=0 skip=1 error=0
```

`examples/risky` is fictional config text. It names the four packages and versions in the bundled snapshot, plus an unpinned package and a package set to `@latest`. The checker does not download those packages. That command exits `1`:

```text
MCP config advisory check
mode: offline

examples/risky/.cursor/mcp.json
  WARN  unpinned  floating  @example/notes-mcp
        version is not pinned
  WARN  latest  moving  @example/docs-mcp@latest
        version is @latest

examples/risky/.mcp.json
  FAIL  malicious-package  GHSA-rvw8-22w3-342v (MAL-2026-18486)  markdown  @ifasn/md-doc-mcp@1.0.4
        GHSA-rvw8-22w3-342v (MAL-2026-18486) lists 1.0.3, 1.0.4, 1.0.5 as a malicious package. No fixed version is listed.
  FAIL  vulnerable-version  GHSA-w766-5x43-whvw  git  mcp-server-git==2026.10.19
        GHSA-w766-5x43-whvw matches affected range < 2026.10.28. Fixed version: 2026.10.28.
  FAIL  vulnerable-version  GHSA-r6mm-377j-qg8m  serverless  awslabs.aws-serverless-mcp-server==0.2.0
        GHSA-r6mm-377j-qg8m matches affected range < 0.2.1. Fixed version: 0.2.1.
  FAIL  vulnerable-version  AWS-2026-152 (GHSA-4prq-p2x5-w9fh, CVE-2026-115413)  awsapi  awslabs.aws-api-mcp-server==1.5.0
        AWS-2026-152 (GHSA-4prq-p2x5-w9fh, CVE-2026-115413) matches affected range >=1.3.0,<1.6.0. Fixed version: 1.6.0.

summary: checked=6 fail=4 warn=2 skip=0 error=0
```

With no path, the script looks for configs that already exist:

- `.mcp.json`
- `.cursor/mcp.json`
- `.vscode/mcp.json`
- `~/.cursor/mcp.json`
- Claude Desktop's `claude_desktop_config.json` (macOS, Windows, and Linux, including `$XDG_CONFIG_HOME` when it is set)

Any path on the command line is read as well. A directory is searched for `.mcp.json`, `mcp.json`, and `claude_desktop_config.json`. A file is read as one config, whatever its name is.

`--offline` does not open a network connection. `--json` prints the same result as JSON (`ok`, `exit_code`, `summary`, `findings`, `skipped`, `errors`). `--snapshot` selects a different snapshot file. The default is `advisory_snapshot.json` next to the script.

## What it reads

Each config may use `mcpServers` (Cursor, Claude Desktop, and portable `.mcp.json`) or `servers` (VS Code). Both keys are read when a file has both. A server entry with `command` and `args` is read when the command is `npx`, `uvx`, `pipx`, or `pip`. A full path or a `.cmd` / `.exe` name is fine. `python -m pip` is read as `pip`. `uv tool run` is read as `uvx`.

From those arguments the script takes the package name and the version. An exact pin is a concrete version after `@` or `==`. A missing version, a range, or `@latest` is a warning. `npx --package`, `uvx --from`, and `pipx run --spec` are read as the package. Extra arguments after the package are left alone.

A server that only has a `url` is skipped. Container commands are skipped. This version does not read image names. A `pip install` that only points at a requirements file is skipped, and that file is not opened.

## Findings

| Result | When |
| --- | --- |
| `FAIL` | The version is in the snapshot's exact malicious list, or inside an affected range, or OSV returns a `MAL-` id or a malicious-package marker for that version. Any other OSV id returned for that version is a `FAIL` too. |
| `WARN` | The version is missing, not an exact pin, or `@latest`. Warnings do not by themselves change a clean exit to a failure. |
| skip | The server is remote, or the command is not one of the package launchers above. |
| error | The file, the snapshot, or a package query could not be used. The process exits `2`. |

Online mode sends one `POST` to `https://api.osv.dev/v1/query` per pinned package. The body is `package.name`, `package.ecosystem` (`npm` or `PyPI`), and `version`. The answer is merged with the snapshot. A network failure, a bad snapshot, or a config that cannot be parsed exits `2`, including when some `FAIL` lines were also found. Those lines are still printed. A partial result is not a clean run. An unpinned package is not sent to OSV, because there is no version to query.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No `FAIL` and no error. `WARN` lines may still be printed. |
| `1` | One or more `FAIL` findings, and no error. |
| `2` | An error blocked a reliable check. |

## Bundled snapshot

`advisory_snapshot.json` holds four public records, verified 2026-11-09:

| Id | Package | Ecosystem | Affected | Fixed |
| --- | --- | --- | --- | --- |
| GHSA-rvw8-22w3-342v (OSV `MAL-2026-18486`) | `@ifasn/md-doc-mcp` | npm | `1.0.3`, `1.0.4`, `1.0.5` | none |
| GHSA-w766-5x43-whvw | `mcp-server-git` | PyPI | `< 2026.10.28` | `2026.10.28` |
| GHSA-r6mm-377j-qg8m | `awslabs.aws-serverless-mcp-server` | PyPI | `< 0.2.1` | `0.2.1` |
| AWS-2026-152 (GHSA-4prq-p2x5-w9fh) | `awslabs.aws-api-mcp-server` | PyPI | `>=1.3.0,<1.6.0` | `1.6.0` |

The fixed version in each range is outside the affected set. `2026.10.28`, `0.2.1`, and `1.6.0` are not failures for those three records. The npm record has no fixed version; only the three listed versions match it.

The snapshot is a local aid. It is not the whole OSV database. Online mode can report other ids OSV returns for the same query.

## What it does not do

- It does not install, download, start, or edit an MCP server or a config file.
- It does not run the package. The only network connection is the optional OSV query above, and only when `--offline` is absent.
- It does not decide that a package is safe. A clean result means this snapshot and, when online, the OSV query did not report the pinned versions you named.
- It does not expand a requirements file, a lockfile, or a container image reference.
- It does not treat a warning as a failed check.

## Authorized use

This project is [MIT licensed](LICENSE). It is for **defensive checks only**.

- Run it on MCP configs you own or are authorized to assess.
- Keep the examples as local fixtures. They are fictional names in JSON files, not instructions to install a package.
- Do not point it at configs you are not allowed to read.

## Tests

From this directory:

```bash
python3 -m unittest -v
```

The tests use the bundled snapshot and do not contact OSV.

## Changelog

### v0.1.0

- Read `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, Cursor's user config, and Claude Desktop's config.
- Accept `mcpServers` and `servers`.
- Extract packages from `npx`, `uvx`, `pipx`, and `pip`.
- Flag the four bundled advisories offline, and merge an OSV query when you are online.
- Warn on an unpinned version or `@latest`.

## Full pack

For more from Digital Fortress:

- **[$79 MCP & Multi-Agent Authorization Security Pack: Trust, Delegation & Audit Evidence](https://fortressaudit.gumroad.com/l/wphmlq?utm_source=github&utm_medium=repo&utm_campaign=mcp-config-advisory-check)**
- **[$99 AI Security & Infrastructure Prompt Pack: LLM Agents, MCP, Kubernetes & Cloud Audits](https://fortressaudit.gumroad.com/l/myyeen?utm_source=github&utm_medium=repo&utm_campaign=mcp-config-advisory-check)**

## Sources

- [OSV query API](https://google.github.io/osv.dev/post-v1-query/)
- [GHSA-rvw8-22w3-342v](https://github.com/advisories/GHSA-rvw8-22w3-342v)
- [OSV MAL-2026-18486](https://osv.dev/vulnerability/MAL-2026-18486)
- [GHSA-w766-5x43-whvw](https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-w766-5x43-whvw)
- [GHSA-r6mm-377j-qg8m](https://github.com/awslabs/mcp/security/advisories/GHSA-r6mm-377j-qg8m)
- [AWS security bulletin 2026-152](https://aws.amazon.com/security/security-bulletins/2026-152-aws/)
- [GHSA-4prq-p2x5-w9fh](https://github.com/awslabs/mcp/security/advisories/GHSA-4prq-p2x5-w9fh)

## License

[MIT](LICENSE) © 2026 Digital Fortress. Authorized defensive use only, as described above.

© 2026 Digital Fortress · github.com/digitalfortressaudit
