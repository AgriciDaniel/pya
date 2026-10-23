#!/usr/bin/env python3
"""Fail when an em dash (U+2014) or en dash (U+2013) appears in any text file
in the repo. Uses git's tracked plus untracked-but-not-ignored files when git
is available, otherwise walks the repo, skipping .git.

Usage: python3 -I tests/check_dashes.py [repo_root]
Exit 0 when clean, 1 when a dash is found or no file was checked.
"""

from __future__ import annotations

import os
import subprocess
import sys

DASHES = {chr(0x2014): "U+2014", chr(0x2013): "U+2013"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2",
              ".ttf", ".otf", ".mp4", ".mov", ".mp3", ".wav", ".pyc"}


def candidates(root):
    try:
        out = subprocess.run(["git", "-C", root, "ls-files", "-co", "--exclude-standard", "-z"],
                             capture_output=True, check=True).stdout.decode("utf-8", "replace")
        paths = [p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        paths = []
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x != ".git"]
            for f in files:
                paths.append(os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/"))
    return [p for p in paths if os.path.splitext(p)[1].lower() not in BINARY_EXT]


def main(argv):
    root = os.path.abspath(argv[0]) if argv else os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    checked = 0
    problems = []
    for rel in candidates(root):
        path = os.path.join(root, rel)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        checked += 1
        for n, line in enumerate(text.splitlines(), 1):
            for ch, name in DASHES.items():
                if ch in line:
                    problems.append(f"{rel}:{n}: {name}")
    for p in problems:
        print(p)
    if checked == 0:
        print("dash check inspected zero files")
        return 1
    print(f"dash check: {checked} files, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
