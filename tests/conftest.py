"""Shared helpers for the PYA test suite."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL = os.path.join(REPO, "skills", "pya")
SCRIPTS = os.path.join(SKILL, "scripts")
FEED_DIR = os.path.join(SKILL, "feed")
FEED = os.path.join(FEED_DIR, "2026-10.json")
SEEDS = os.path.join(SKILL, "references", "seeds.json")
FIXTURES = os.path.join(REPO, "tests", "fixtures")
TODAY = "2026-10-23"


def nonvacuous(count, what):
    """A checker that inspected zero items must fail, never pass silently."""
    assert isinstance(count, int) and count > 0, f"checker inspected zero {what}"
    return count


def run_script(name, *args, env=None, stdin=None):
    """Run a PYA script the way the orchestrator does (python3 -I)."""
    full_env = dict(os.environ)
    full_env["PYA_TODAY"] = TODAY
    if env:
        full_env.update(env)
    proc = subprocess.run(
        [sys.executable, "-I", os.path.join(SCRIPTS, name), *args],
        capture_output=True, text=True, env=full_env, input=stdin, timeout=120,
    )
    data = None
    if proc.stdout.strip():
        data = json.loads(proc.stdout)
    return proc.returncode, data, proc.stderr


def load_module(name):
    if SCRIPTS not in sys.path:
        sys.path.insert(0, SCRIPTS)
    spec = importlib.util.spec_from_file_location(f"pya_{name}", os.path.join(SCRIPTS, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def common():
    return load_module("_pya_common")


@pytest.fixture(scope="session")
def feed():
    with open(FEED, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="session")
def seeds_doc():
    with open(SEEDS, encoding="utf-8") as fh:
        return json.load(fh)


def write(root, rel, content, mode="w"):
    path = os.path.join(str(root), rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as fh:
        fh.write(content)
    return path
