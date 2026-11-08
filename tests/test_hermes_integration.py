"""End-to-end through a real Hermes install: the plugin is loaded by Hermes's own plugin manager and
a ``terminal`` call goes through ``model_tools.handle_function_call`` (the path every model tool call
takes) with real gateway session identity bound. Skipped when Hermes is not importable.

Run with Hermes's interpreter, e.g. ``~/.hermes/hermes-agent/.venv/bin/python -m pytest -q``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

try:  # noqa: SIM105
    import hermes_cli  # noqa: F401

    HAVE_HERMES = True
except Exception:  # pragma: no cover
    HAVE_HERMES = False

pytestmark = pytest.mark.skipif(not HAVE_HERMES, reason="Hermes is not importable in this interpreter")

DRIVER = textwrap.dedent(
    """
    import json, sys
    from hermes_cli.plugins import get_plugin_manager
    get_plugin_manager().discover_and_load(force=True)
    import model_tools
    from gateway.session_context import set_session_vars, clear_session_vars

    from hermes_cli.plugins import get_plugin_command_handler

    def call(platform, uid, label):
        tokens = set_session_vars(platform=platform, user_id=uid, user_name=label, chat_id="-1", chat_type="group")
        try:
            return model_tools.handle_function_call("terminal", {"command": "echo clearance-ran"}, task_id="t-" + label)
        finally:
            clear_session_vars(tokens)

    out = {}
    for label, platform, uid in (("guest", "telegram", "2002"), ("admin", "telegram", "1001"), ("local", "", "")):
        out[label] = call(platform, uid, label)

    # Promote then demote the guest through the real /clearance handler and Hermes's real settings writer.
    clearance = get_plugin_command_handler("clearance")
    out["set"] = clearance("set telegram:2002 admin", platform="cli", source=None)
    out["promoted"] = call("telegram", "2002", "promoted")
    out["unset"] = clearance("unset telegram:2002", platform="cli", source=None)
    import time; time.sleep(3.2)  # past the policy cache TTL as well
    out["demoted"] = call("telegram", "2002", "demoted")
    print("RESULT" + json.dumps(out))
    """
)


def _run(tmp_path: Path) -> dict:
    home = tmp_path / "hermes-home"
    (home / "plugins").mkdir(parents=True)
    shutil.copytree(ROOT, home / "plugins" / "clearance", ignore=shutil.ignore_patterns(".git", "__pycache__", "tests"))
    (home / "config.yaml").write_text(
        "plugins:\n  enabled: [clearance]\n  entries:\n    clearance:\n      settings:\n"
        "        users:\n          telegram:1001: admin\n"
        "terminal:\n  backend: local\n",
        encoding="utf-8",
    )
    env = dict(os.environ, HERMES_HOME=str(home))
    proc = subprocess.run([sys.executable, "-c", DRIVER], capture_output=True, text=True, env=env,
                          timeout=240, cwd=str(tmp_path))
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"driver failed:\nSTDOUT:\n{proc.stdout[-2000:]}\nSTDERR:\n{proc.stderr[-4000:]}"
    return json.loads(line[len("RESULT"):]), home


def test_real_dispatch_blocks_guest_and_allows_admin(tmp_path):
    out, home = _run(tmp_path)
    assert "[clearance]" in out["guest"] and "clearance-ran" not in out["guest"]
    assert "clearance-ran" in out["admin"]
    assert "clearance-ran" in out["local"]
    assert out["set"] == "telegram:2002 is now admin." and "clearance-ran" in out["promoted"]
    assert out["unset"] == "telegram:2002 is now guest."
    assert "[clearance]" in out["demoted"] and "clearance-ran" not in out["demoted"]  # demotion really landed
    audit = (home / "plugin-data" / "clearance" / "audit.jsonl").read_text(encoding="utf-8")
    assert '"who": "telegram:2002"' in audit and '"tool": "terminal"' in audit
