"""Version and source identity for portable-disc-workflow."""
# SPDX-License-Identifier: GPL-3.0-only

import hashlib
import os
from pathlib import Path
import subprocess
from functools import lru_cache

PROGRAM_VERSION = "0.1.0-dev.13-public.1"


@lru_cache(maxsize=1)
def _discover():
    script_dir = Path(__file__).resolve().parent
    root = script_dir.parent
    names = sorted(name for name in os.listdir(script_dir)
                   if name == "portable-disc-workflow.py" or
                   (name.startswith("portable_disc_") and name.endswith(".py")))
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode("utf-8") + b"\0")
        digest.update((script_dir / name).read_bytes())
    revision = dirty = None
    marker = root / ".git"
    if marker.is_dir() or marker.is_file():
        paths = ["scripts/" + name for name in names]
        try:
            revision = subprocess.run(
                ["git", "rev-parse", "--verify", "HEAD"], cwd=str(root),
                capture_output=True, text=True, timeout=3, check=True,
            ).stdout.strip() or None
            status = subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=all", "--", *paths],
                cwd=str(root), capture_output=True, text=True, timeout=3, check=True,
            ).stdout
            dirty = bool(status)
        except (OSError, subprocess.SubprocessError):
            revision = dirty = None
    return revision, dirty, digest.hexdigest()


def program_stamp():
    revision, dirty, source_hash = _discover()
    return {"program": {"version": PROGRAM_VERSION, "source_revision": revision,
                        "source_dirty": dirty, "source_sha256": source_hash}}


def version_text():
    revision, dirty, _ = _discover()
    source = revision[:12] if revision else "unknown"
    state = "dirty" if dirty else "clean" if dirty is False else "state unknown"
    return f"portable-disc-workflow {PROGRAM_VERSION} (source {source}, {state})"
