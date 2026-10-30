#!/bin/sh
# Usage: docker run --rm -v <dir with the release wheel and sdist>:/dist:ro python:3.12-slim sh /dist/clean_install_check.sh
# (copy this script into that directory first). Needs network access to PyPI for the dependencies.
# Clean-environment install test: official python:3.12-slim, nothing preinstalled, the real release artifacts,
# dependencies resolved from PyPI exactly as a user's install would.
set -eu
echo "== environment"; head -1 /etc/os-release; uname -m; python3 --version
pip --version | cut -c1-30
echo "== 1. pip install, pinned, from the release wheel (dependencies from PyPI)"
python3 -m venv /tmp/venv
/tmp/venv/bin/pip install -q --disable-pip-version-check --find-links /dist "nifimcp-server==0.1.0rc1"
/tmp/venv/bin/pip show nifimcp-server | grep -E "^(Name|Version|Location)"
/tmp/venv/bin/nifimcp --version
echo "== 2. README quickstart with the installed command"
/tmp/venv/bin/nifimcp demo --output /tmp/demo >/tmp/demo.json
python3 -c "import json;d=json.load(open('/tmp/demo.json'));print('demo:',d['investigation_status'],[t['status'] for t in d['tools']],[x['status'] for x in d['drafts']])"
test -s /tmp/demo/report.html && echo "report.html $(wc -c </tmp/demo/report.html) bytes"
echo "== 3. uv tool install from the release wheel, as the README documents"
/tmp/venv/bin/pip install -q --disable-pip-version-check uv
export PATH="/root/.local/bin:$PATH"
/tmp/venv/bin/uv tool install --find-links /dist "nifimcp-server==0.1.0rc1"
nifimcp --version
echo "== 4. uvx one-liner from the README (resolves the wheel from /dist, deps from PyPI)"
/tmp/venv/bin/uvx --find-links /dist --from "nifimcp-server==0.1.0rc1" nifimcp demo --output /tmp/demo2 >/dev/null
test -s /tmp/demo2/report.html && echo "uvx demo ok"
echo "== 5. MCP host form: uvx ... nifimcp serve over stdio, driven by the official MCP client"
printf '{"schema_version":"1","mode":"demo","artifact_dir":"/tmp/art"}\n' > /tmp/operator.json
/tmp/venv/bin/python - <<'PY'
import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client
async def main():
    params = StdioServerParameters(command="/tmp/venv/bin/uvx", args=["--find-links", "/dist", "--from", "nifimcp-server==0.1.0rc1", "nifimcp", "serve", "--config", "/tmp/operator.json"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            res = await s.call_tool("describe_flow", {"scope_id": "demo-telemetry-intake"})
            env = res.structured_content
            assert not res.is_error and env["status"] in ("ok", "partial"), env.get("error")
            print("server", init.server_info.name, init.server_info.version, "-", len(tools), "tools; describe_flow:", env["status"], len(env["findings"]), "findings")
anyio.run(main)
PY
echo "== 6. sdist installs too"
/tmp/venv/bin/pip install -q --disable-pip-version-check --force-reinstall --no-deps /dist/nifimcp_server-0.1.0rc1.tar.gz
/tmp/venv/bin/nifimcp --version
echo "CLEAN ENVIRONMENT INSTALL PASSED"
