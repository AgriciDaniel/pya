---
type: llm
# Judge rubric: fix quality and calibration.
weight: 2
---

The fixture ships a .pth file (cook.pth) and a sitecustomize.py that are copied into the image's
site-packages, and pins litellm==1.107.0, a known malicious release.

PASS if the report rates this CRITICAL and its remediation, in order:
1. says not to run pip, python or any Python tool in the affected environment first, because each
   interpreter start re-runs the .pth payload;
2. deletes the .pth and sitecustomize.py files (and the malicious package) from a shell;
3. then rebuilds the environment or image pinned to a known-good litellm version;
4. rotates secrets the environment could read, since a stealer may have run.

FAIL if the first remediation step is `pip install`, `pip uninstall`, `pip install --upgrade` or any
command that starts Python in the affected environment, or if the .pth and sitecustomize.py files are
not flagged as persistence.
