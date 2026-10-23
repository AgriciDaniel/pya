# PYA threat feed

The feed is a dated JSON file of package, image and runtime versions, plus indicators, that PYA checks a repository against. One file covers one month: `YYYY-MM.json`. `schema.json` defines the format, and `scripts/feed_match.py` and `scripts/ioc_scan.py` always pick the newest file.

Permanent techniques (patterns that stay true after the month is over) do not belong here. They go in `references/seeds.json`, which has its own tests.

## How a monthly feed is produced

1. **Start from the verified digest.** Each month's verified digest (for October 2026: "Developer and Infrastructure Security Digest_ Sept 23 to Oct 23, 2026 (v2, verified).md") is the only input. Unverified first drafts are not used.
2. **Take the actionable items that a repository can show.** That means a version in a lockfile, manifest, plugin header, image tag or runtime pin, or an indicator in a file. Skip items that live only on a host (kernel, desktop apps, GPU drivers, host trust stores) or that have no fixed version yet.
3. **Write one entry per item.** Each entry needs:
   - `id`: `PYA-YYYY-MM-NNN`, numbered in file order. Never reuse an id.
   - `kind`, `ecosystem` and `package` exactly as the parsers see them: npm names as published, PyPI names in any case, WordPress plugin slugs, Docker repositories without the registry host (`gitroomhq/postiz-app`, `gitlab/gitlab-ce`), and `runtime` for node, php, docker, podman and bun.
   - Affected versions as OSV-style `ranges` (`introduced` plus `fixed` or `last_affected`) or exact `versions`. Give each maintained branch its own range so a patched backport is not flagged. Put end-of-life lines in a range whose `fixed` is the next supported line.
   - `severity`, `malicious`, and `kev: true` only when the digest says the CVE is in CISA KEV.
   - `confidence`: `confirmed`, unless the digest marks the item as secondary-source only (`secondary`) or lists it under unverified items (`unverified`).
   - `iocs` for indicators. Store domains and IP addresses as `regex` with escaped dots (`imgcdn1\.com`), and write them defanged in notes (`imgcdn1[.]com`). Never store a clickable live malicious URL. The validator rejects the `domain` and `ip` types for this reason.
   - `response_order` when the order of the fix matters. Use only keys from `references/response-order.md`.
   - `sources`: at least one https URL, copied exactly from the digest's Sources list. `digest_ref` names the digest section, for example `D§11`.
4. **Set the dates.** `as_of` is the digest's verification date. `expires` is about five weeks later (for 2026-10: `2026-11-27`). The report prints the feed month, `as_of` and its age, and warns once the feed is more than 35 days old.
5. **Validate and test** (below), then commit the new file next to the older ones. Old feeds stay for history; the scripts only read the newest.

## Rules

- Every entry cites at least one source from the digest. No source, no entry.
- Entries are confirmed facts from the digest, not guesses. When the digest corrects an advisory (Postiz: the fix is 2.24.0, while the advisory data says 2.4.0), follow the digest and say why in `advice`.
- No em or en dashes anywhere in the file.
- A feed match is a lead for the dependency agent to confirm, not a finding by itself. No match means nothing in the parsed files matched, not that the repo is safe.

## Validate

```text
python3 -I skills/pya/scripts/validate_feed.py skills/pya/feed/2026-10.json
make check-ci
```

`validate_feed.py` uses only the standard library. It checks required and unknown fields, the id pattern and month, unique ids, enums, dates (`expires` after `as_of`), https sources, IOC regexes that compile, `response_order` keys and the dash rule. It exits 1 on any error. `make check-ci` also runs the pytest suite, which matches the fixtures in `tests/fixtures/` against the feed.

## KEV

`scripts/update_kev.py` downloads the CISA KEV catalog to `~/.cache/pya/kev.json`. It only runs when you ask for it. The only other network use is `run_tools.py` with `--online`, which lets the optional scanners go online. When that snapshot exists, `feed_match.py` also flags `kev` for any matched entry whose CVE alias is in the catalog.
