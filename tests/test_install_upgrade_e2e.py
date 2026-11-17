# © 2026 TrinTech Digital Defense — isolated installer integration tests
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd, cwd, env=None, check=True):
    merged = os.environ.copy()
    # Git exports repository/object-database variables to child processes.
    # They can corrupt local bare-repository transport in this isolated lab
    # (notably GIT_OBJECT_DIRECTORY and GIT_ALTERNATE_OBJECT_DIRECTORIES).
    # Each command must resolve its repository from its own cwd/arguments.
    for key in tuple(merged):
        if key.startswith("GIT_"):
            merged.pop(key)
    if env:
        merged.update(env)
    return subprocess.run(
        cmd, cwd=cwd, env=merged, text=True, capture_output=True, check=check
    )


@pytest.fixture
def installer_lab(tmp_path):
    """Build an isolated bare origin, seed repo, checkout, and harmless Python shim."""
    seed = tmp_path / "seed"
    checkout = tmp_path / "Sentinel"
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()

    seed.mkdir()
    _run(["git", "init"], seed)
    _run(["git", "config", "user.email", "sentinel-test@example.invalid"], seed)
    _run(["git", "config", "user.name", "Sentinel Installer Test"], seed)
    (seed / "README.md").write_text("base\n", encoding="utf-8")
    (seed / "setup.py").write_text("# setup stub\n", encoding="utf-8")
    (seed / "sentinel.py").write_text("# engine stub\n", encoding="utf-8")
    _run(["git", "add", "."], seed)
    _run(["git", "commit", "-m", "initial"], seed)
    _run(["git", "branch", "-M", "main"], seed)
    # Use the seed repository itself as the local upstream. This still exercises
    # real clone/fetch/fast-forward behavior without receive-pack, which is broken
    # in some Android/proot filesystems used by developers.
    _run(["git", "clone", "--branch", "main", str(seed), str(checkout)], tmp_path)

    # The installer only needs Python to be discoverable and to return success
    # for the setup/compile calls; this shim prevents executing project setup.
    python_shim = shim_dir / "python3"
    python_shim.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    python_shim.chmod(0o755)

    env = {
        "SENTINEL_HOME": str(checkout),
        "SENTINEL_REPO": str(seed),
        "SENTINEL_BRANCH": "main",
        "PATH": str(shim_dir) + os.pathsep + os.environ.get("PATH", ""),
    }
    return {"seed": seed, "checkout": checkout, "env": env}


def _remote_commit(lab, filename, content, message):
    seed = lab["seed"]
    (seed / filename).write_text(content, encoding="utf-8")
    _run(["git", "add", filename], seed)
    _run(["git", "commit", "-m", message], seed)


def _install(lab):
    return _run(
        ["bash", str(ROOT / "install.sh")],
        ROOT,
        env=lab["env"],
        check=False,
    )


def test_installer_runs_clean_fast_forward_in_isolated_git_lab(installer_lab):
    lab = installer_lab
    _remote_commit(lab, "README.md", "updated upstream\n", "upstream update")

    result = _install(lab)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (lab["checkout"] / "README.md").read_text(encoding="utf-8") == "updated upstream\n"
    local_head = _run(["git", "rev-parse", "HEAD"], lab["checkout"]).stdout.strip()
    remote_head = _run(["git", "rev-parse", "refs/heads/main"], lab["seed"]).stdout.strip()
    assert local_head == remote_head


def test_installer_preserves_conflicting_dirty_file_and_stops(installer_lab):
    lab = installer_lab
    local_file = lab["checkout"] / "README.md"
    local_file.write_text("operator local edit\n", encoding="utf-8")
    _remote_commit(lab, "README.md", "upstream conflicting edit\n", "conflicting upstream edit")

    result = _install(lab)

    assert result.returncode != 0
    assert local_file.read_text(encoding="utf-8") == "operator local edit\n"
    assert "Fast-forward failed" in result.stdout


def test_installer_preserves_untracked_file_during_fast_forward(installer_lab):
    lab = installer_lab
    note = lab["checkout"] / "operator-notes.txt"
    note.write_text("keep this local file\n", encoding="utf-8")
    _remote_commit(lab, "CHANGELOG.md", "upstream change\n", "unrelated upstream change")

    result = _install(lab)

    assert result.returncode == 0, result.stdout + result.stderr
    assert note.read_text(encoding="utf-8") == "keep this local file\n"
    assert (lab["checkout"] / "CHANGELOG.md").exists()


def test_installer_preserves_local_commit_when_branches_diverge(installer_lab):
    lab = installer_lab
    checkout = lab["checkout"]
    (checkout / "local-only.txt").write_text("local commit\n", encoding="utf-8")
    _run(["git", "add", "local-only.txt"], checkout)
    _run(["git", "config", "user.email", "operator@example.invalid"], checkout)
    _run(["git", "config", "user.name", "Local Operator"], checkout)
    _run(["git", "commit", "-m", "local-only commit"], checkout)
    local_head_before = _run(["git", "rev-parse", "HEAD"], checkout).stdout.strip()
    _remote_commit(lab, "remote-only.txt", "remote commit\n", "remote-only commit")

    result = _install(lab)

    assert result.returncode != 0
    assert _run(["git", "rev-parse", "HEAD"], checkout).stdout.strip() == local_head_before
    assert (checkout / "local-only.txt").read_text(encoding="utf-8") == "local commit\n"
