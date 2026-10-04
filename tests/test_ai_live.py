"""Against a real Ollama (CI starts the ollama/ollama container with a small model).

Enabled with PULSEOPS_TEST_OLLAMA_MODEL=<model> (and optionally PULSEOPS_TEST_OLLAMA_URL).
"""
import os
import subprocess
import sys

import pytest

MODEL = os.environ.get("PULSEOPS_TEST_OLLAMA_MODEL")
URL = os.environ.get("PULSEOPS_TEST_OLLAMA_URL", "http://127.0.0.1:11434")
CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cli.py")

pytestmark = pytest.mark.skipif(not MODEL, reason="PULSEOPS_TEST_OLLAMA_MODEL not set")


def pulseops(tmp_path, *args):
    cfg = tmp_path / "config" / "pulseops"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "config.toml").write_text(f'[ai]\nurl = "{URL}"\nmodel = "{MODEL}"\ntimeout = 600\n')
    env = dict(os.environ, XDG_CONFIG_HOME=str(tmp_path / "config"), HOME=str(tmp_path))
    r = subprocess.run([sys.executable, CLI, *args], env=env, capture_output=True, text=True, timeout=900)
    return r.returncode, r.stdout, r.stderr


def test_status_and_explain_with_a_real_model(tmp_path):
    code, out, err = pulseops(tmp_path, "ai", "status")
    assert code == 0, err
    assert f"{MODEL} hazır" in out

    code, out, err = pulseops(tmp_path, "ai", "explain", "--demo")
    assert code == 0, err
    assert len(out.strip()) > 50
    assert "\x1b" not in out  # sanitized even if the model emits escapes
    print(out)  # visible in the CI log for a human sanity check

    code, out, err = pulseops(tmp_path, "ai", "ask", "--demo", "Hangi port dışa açık ve riskli?")
    assert code == 0, err and out.strip()
    print(out)
