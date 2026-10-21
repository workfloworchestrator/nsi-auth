# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`nsi-auth` is an external authorization endpoint for ingress-nginx, Traefik and Envoy Gateway. The
proxy terminates mTLS and forwards the client's identity in one header; `GET|POST|... /validate`
answers 200 with `X-Auth-Method: mTLS` and `X-Client-DN` when the subject DN is on the allowlist,
403 otherwise. `README.md` has the per-proxy setup and the configuration table.

## Commands

```bash
uv sync                                         # install runtime + dev deps
uv run pytest                                   # all tests (CI)
uv run pytest tests/unit/test_rfc4514_cmp.py -k name_attrs   # one file / one test
uv run ruff check . && uv run ruff format --check .           # lint + format (CI)
uv run mypy nsi_auth.py rfc4514_cmp.py          # types (CI checks these two files only)

# Container; VERSION is required, see Versioning
docker build --build-arg VERSION="$(uvx --from setuptools-scm python -m setuptools_scm)" -t nsi-auth .
```

## Architecture

Two top-level modules, no package:

- `nsi_auth.py` — the Flask app (served by uvicorn with `--interface wsgi`). Everything happens at
  import: `Settings()` reads the environment (no prefix), the app is created, and a thread starts
  watching the allowlist file (`watch_file` polls `st_mtime_ns` every 5 s; `USE_WATCHDOG` switches to
  inotify, which misses Kubernetes ConfigMap symlink swaps). `_CODECS` maps each
  `TLS_CLIENT_AUTHN_FORMAT` to one parser in `rfc4514_cmp`; supporting a new proxy is one entry there
  plus its parser.
- `rfc4514_cmp.py` — turns each header format (RFC 2253 DN, PEM, Traefik minimized PEM / cert-info,
  Envoy XFCC `Cert=` / `Subject=`) and each allowlist line into a `cryptography` `x509.Name`, and
  `name_attrs` reduces a name to a frozenset of `(OID, value)` pairs.

`validate()` compares `name_attrs` sets, not `x509.Name` objects: `Name.__eq__` is RDN-order
sensitive, and proxies serialize the same subject in different orders and with dotted OIDs instead
of friendly names (`names2oid` adds the ones `cryptography` lacks, e.g. `GN`, `SN`,
`organizationIdentifier`, `emailAddress`).

## Invariants

- **One header, one codec, no fallback.** Only `TLS_CLIENT_SUBJECT_AUTHN_HEADER` is read, so a client
  cannot influence the result through another identity header; a missing or unparseable value is a
  403, never a retry with a different codec.
- **`/validate` accepts every method.** Envoy ext_authz mirrors the downstream method onto the auth
  subrequest; GET-only would 405 every SOAP POST to safnari/pce.
- **Both modules must be in the wheel.** The container installs the wheel built from
  `[tool.setuptools] py-modules`; a new top-level module needs adding there and to the Dockerfile's
  build-stage `COPY`.
- **Tests import `nsi_auth` once, after setting env vars.** `Settings` validates
  `allowed_client_subject_dn_path` as an existing file at import, so `tests/conftest.py`'s
  `make_application` sets the environment before the first import and mutates `settings`/`state`
  for later reconfigurations, restoring them afterwards.

## Helm chart and CA bundle

`chart/` is published as `oci://ghcr.io/workfloworchestrator/charts/nsi-auth`. `templates/secret.yaml`
renders `{{ .Release.Name }}-ca` with `ca.crt` = `chart/files/cacert.pem` + `config.additionalTrustedCA`.
Proxies use that Secret to verify client certificates, and other NSI apps reuse it as their outbound
truststore, so a bundle change affects both directions.

- Update `cacert.pem` from `https://curl.se/ca/cacert.pem` and check it against
  `https://curl.se/ca/cacert.pem.sha256`; list added and removed roots in the commit.
- Set `additionalTrustedCA` to `""` rather than leaving it unset: unset renders `%!s(<nil>)` into
  the bundle.

## Versioning

The version is the git tag; never edit it. `pyproject.toml` is `dynamic = ["version"]` with
setuptools-scm, so a tag builds `0.3.4` and any other commit builds `0.3.5.dev<n>+g<sha>`. Chart
version = app version = tag. The container build has no `.git`, so the workflow passes
`--build-arg VERSION`, which the `Dockerfile` exports as `SETUPTOOLS_SCM_PRETEND_VERSION_FOR_NSI_AUTH`;
omitting it fails the build by design.

## Dependency cooldown

`exclude-newer = "8 days"` in `pyproject.toml` and `minimumReleaseAge` in `.github/renovate.json`
must stay equal. uv enforces the cooldown on indirect dependencies, which Renovate cannot. An urgent
fix younger than that needs a temporary `exclude-newer-package = { <pkg> = false }`. Lock file
maintenance sets `minimumReleaseAge` to `null`: it has no release timestamp, so Renovate would keep
`renovate/stability-days` pending forever and never automerge it.

## Code style

- Line length 120; ruff with Google docstrings and `max-complexity = 7`; tests exempt from
  `ANN`/`S101`.
- Python 3.13 in CI and the image; `requires-python` still allows 3.11.
- Apache-2.0 header on every `.py` file.
