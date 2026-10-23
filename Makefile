# PYA developer checks. Standard library Python 3.10+ and pytest only.
#   make check-ci  pytest, feed validation, seed coverage, dash check (what CI runs)
#   make check     check-ci plus shellcheck and claude plugin validate --strict when installed

PY ?= python3
FEEDS := $(sort $(wildcard skills/pya/feed/20*.json))
SH_FILES = $(shell git ls-files -co --exclude-standard '*.sh' 2>/dev/null)

.PHONY: check check-ci test feeds seeds dashes shellcheck plugin-validate

check-ci: test feeds seeds dashes

check: check-ci shellcheck plugin-validate

test:
	$(PY) -m pytest -q

feeds:
	@test -n "$(FEEDS)" || { echo "no feed files found in skills/pya/feed"; exit 1; }
	$(PY) -I skills/pya/scripts/validate_feed.py $(FEEDS)

seeds:
	$(PY) -m pytest -q tests/test_seeds.py

dashes:
	$(PY) -I tests/check_dashes.py

shellcheck:
	@if command -v shellcheck >/dev/null 2>&1; then \
	  test -n "$(SH_FILES)" || { echo "no shell scripts found"; exit 1; }; \
	  echo "shellcheck $(SH_FILES)"; shellcheck $(SH_FILES); \
	else echo "shellcheck not installed, skipped"; fi

plugin-validate:
	@if command -v claude >/dev/null 2>&1; then \
	  echo "claude plugin validate . --strict"; claude plugin validate . --strict; \
	else echo "claude not installed, plugin validate skipped"; fi
