# Response Order

Some fixes cause damage when done in the wrong order. When a finding matches one of these keys,
set `response_order` to the key and print the steps in the finding under `Response order:`.
Steps are written for the repo owner, not for PYA: PYA never runs them.

| Key | When it applies |
|---|---|
| `tensorlake-wiper` | Malware that watches a stolen token and wipes data when the token is revoked |
| `litellm-pth` | Python startup-hook malware (`.pth`, `sitecustomize.py`, `usercustomize.py`) |
| `updraft-backdoor` | WordPress backdoor plugins installed through a remote-management key |
| `wp-sc-backdoor` | Self-healing PHP or WordPress backdoors with off-disk copies |
| `php-fpm-restart` | PHP runtime fixes that only apply after workers restart |
| `rebuild-images` | Fixes that live in base images, vendored CA bundles or CI caches |
| `rotate-on-exposure` | Any secret found exposed, or a credential stealer that actually ran |
| `emsign-trust` | Clients that still trust the compromised eMudhra/emSign keys |

## tensorlake-wiper

Source: the digest's section 12, which cites https://checkmarx.com/zero-post/mini-shai-hulud-in-tensorlake-a-token-monitor-that-can-wipe-your-home-directory/ and https://stepsecurity.io/blog/tensorlake-npm-compromised-hostage-token-worm.

1. Isolate the machine from the network.
2. Stop and remove the monitor **first**. On Linux this is a systemd user service, with files in `~/.local/bin` and `~/.config`.
3. Only then revoke the tokens, from a different, clean machine. Revoking first triggers the wipe.
4. Rotate npm, GitHub and cloud tokens, and install the clean package version.

## litellm-pth

Source: https://docs.litellm.ai/blog/security-incident-oct-21-2026

1. Do **not** run `pip`, `python` or any Python tool in the affected environment. Every interpreter start re-runs a `.pth` payload.
2. Delete the `.pth`/`sitecustomize.py` files and the malicious `*.dist-info` from a shell.
3. Kill any loader process (for LiteLLM: the one holding `/tmp/remote_code_loader.lock`).
4. Rebuild the environment or image from scratch, pinned to a known-good version.
5. Rotate every secret the environment could read (cloud roles, provider keys, database URLs). See `rotate-on-exposure`.

## updraft-backdoor

Sources: https://patchstack.com/articles/updraftcentral-key-compromise-wordpress-backdoors/ and https://teamupdraft.com/blog/security-incident-october-2026/

1. In each site's own wp-admin (not through the remote console), delete every remote-management key.
2. Then remove the backdoor plugins, including Must-Use plugins. Do **not** repair a broken backdoor plugin: fixing its error turns it on.
3. Count admin and editor users directly in the database. Look for unknown option names (for UpdraftCentral: `_sync_token`).
4. Check for `wp-sc-backdoor` persistence before calling the site clean.
5. If the site was compromised, restore a backup taken before the compromise, then rotate salts, admin passwords and database credentials.

## wp-sc-backdoor

Source: https://blog.sucuri.net/2026/09/sc-wordpress-malware-a-self-healing-mesh-of-loaders-drop-ins-and-a-blockchain-controlled-backdoor.html

1. Neutralize the loader first: the `auto_prepend_file` line in `.user.ini`.
2. Remove the off-disk copies next: options-table payloads, shared-memory segments, cron entries and database triggers.
3. Delete the files last. Deleting files first lets the other copies restore them.

## php-fpm-restart

Source: https://www.php.net/

1. Update PHP through the distro or the vendor repository.
2. Restart **every** PHP-FPM pool. Bugs that live in worker state survive until the workers restart.
3. Confirm the version on the running pool (a phpinfo check), not only with `php -v` on the CLI.

## rebuild-images

1. Bump the pinned base image or package.
2. Rebuild with no cache, including CI runner images and dependency caches.
3. Redeploy, then confirm the running version in the deployed artifact.

## rotate-on-exposure

Source: the digest's "Secrets to rotate" list.

Rotate a secret only when there is evidence of exposure. Evidence means one of these:

- the secret is committed or logged;
- a stealer ran;
- a platform disclosed a breach.

Rotate at the source, then update consumers, then revoke the old value.

Order matters when malware is still present. Remove persistence first; see `tensorlake-wiper`.

Do not recommend reflexive rotation for findings that do not expose a secret, such as a TLS trust problem with no interception evidence.

## emsign-trust

Source: https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576/

1. Update the client trust store: pip, certifi, uv, conda, the OS `ca-certificates` package, and any vendored bundle such as WordPress `wp-includes/certificates/ca-bundle.crt`.
2. Bootstrap pip from the hash-pinned wheel in the Python advisory when the network may be hostile.
3. Rebuild images and CI caches (see `rebuild-images`).
4. Rotate secrets only if a stale client ran on an untrusted network after the keys became public.
