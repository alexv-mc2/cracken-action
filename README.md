# crAcken CI upload

Upload an existing JSON SBOM to the crAcken public API v1. Optionally wait for analysis, count findings across every results page and fail the build at a severity threshold. The composite GitHub Action and CI snippets use the same [scripts/upload.sh](scripts/upload.sh), adapted from crAcken's tested API example. Set `generate: syft` to generate a CycloneDX JSON SBOM inside your CI before uploading it. The default `generate: none` keeps the existing upload behavior.

An operator must enable the API in your environment. These files and local tests do not establish production availability. Copy the actual API base URL from crAcken's API keys page, retaining its path prefix. Examples use this placeholder:

```text
https://<your-crAcken-API-host>/functions/v1/api-v1
```

## GitHub Action

For the default upload mode, make an SBOM from your build available in the workspace before this step. Configure the repository's private-action access policy for authorised consumers while this repository is private. Replace the pin with a reviewed full commit SHA:

```yaml
- uses: alexv-mc2/cracken-action@REPLACE_WITH_FULL_COMMIT_SHA
  id: cracken
  with:
    api-url: https://<your-crAcken-API-host>/functions/v1/api-v1
    api-token: ${{ secrets.CRACKEN_API_KEY }}
    project: ${{ vars.CRACKEN_PROJECT_ID }}
    release: ${{ github.sha }}
    sbom-file: bom.json
    wait: 'true'
    fail-on: high
```

A [complete workflow example](examples/github.yml) uses a self-hosted runner. The runner needs Bash for the composite step, POSIX `sh`, curl **7.76+**, `jq`, `mktemp`, `date`, standard Unix utilities, and `sha256sum` or `shasum`. Generation additionally needs `tar`; it downloads a verified syft binary only when the requested version is unavailable on PATH.

### Inputs

The environment column also describes the standalone script and GitLab job variables. Store secrets through your CI secret manager.

| Action input | Environment variable | Default / meaning |
|---|---|---|
| `api-url` | `CRACKEN_API_URL` | Required API base URL, including `/functions/v1/api-v1` |
| `api-token` | `CRACKEN_API_KEY` | Required secret service-account API key |
| `project` | `CRACKEN_PROJECT_ID` | Existing product UUID; maps to POST `project_id` |
| `product` | `CRACKEN_PRODUCT_ID` | Alias of `project`; do not set both |
| `project-slug` | `CRACKEN_PROJECT_SLUG` | Existing product slug; maps to POST `project_slug` |
| `release` | `VERSION` | Version, 1–100 characters after trimming; maps to POST `version` |
| `release-id` | `CRACKEN_RELEASE_ID` | Existing empty release UUID; maps to POST `release_id` |
| `sbom-file` | `SBOM_FILE` | Empty: try `bom.json`, then `sbom.cdx.json`, then exactly one `*.spdx.json` in the current directory; multiple SPDX candidates fail |
| `generate` | `CRACKEN_GENERATE` | `none`; `none` uploads an existing file, `syft` generates then uploads; incompatible with an explicit `sbom-file` |
| `syft-version` | `SYFT_VERSION` | `1.55.0`; exact stable version without the `v` prefix |
| `scan-path` | `SCAN_PATH` | `.`; directory to scan inside the customer CI workspace |
| `syft-insecure-skip-pin` | `SYFT_INSECURE_SKIP_PIN` | `false`; explicitly accept an unpinned custom syft version (see below) |
| `wait` | `WAIT` | `false`; accepts `true`/`false` or `1`/`0` |
| `fail-on` | `FAIL_ON` | `none`; one of `none`, `critical`, `high`, `medium`, `low`; a severity forces waiting |
| `timeout` | `TIMEOUT` | `900` seconds; positive integer, maximum `86400`, for upload and subsequent waiting |

Choose exactly one target: `project` (or its `product` alias) plus `release`; `project-slug` plus `release`; or `release-id` alone. Products must already exist. Each active release accepts one SBOM. An identical rerun uses a deterministic idempotency key; sending different content to the same occupied release returns HTTP 409. Use a new version for a different SBOM. The GitLab template defaults an empty `VERSION` to the tag or short commit SHA, unless targeting `CRACKEN_RELEASE_ID`. The Action requires an explicit `release` for product targets.

### Outputs

| Output | Value |
|---|---|
| `sbom-path` | Generated SBOM path, only with `generate: syft`; retained for later artifact steps in the same job |
| `upload-id` | API `sbom_upload_id` |
| `analysis-id` | API `analysis_id` |
| `analysis-status` | Latest observed status; `queued` after upload without waiting |
| `critical`, `high`, `medium`, `low`, `none`, `unknown` | Counts by normalized severity; empty without waiting |
| `app-url` | Release/app link returned by the API, when present; may be relative to the crAcken app |

GitHub receives these through `$GITHUB_OUTPUT`. After all findings pages have been read, `$GITHUB_STEP_SUMMARY` contains severity counts only. The script never prints individual findings or SBOM content. Failed steps can have only the outputs reached before failure; use the step's exit result to decide success.

## Waiting and severity policy

Upload needs `sbom:write`. Waiting, counting and severity gating also need `analysis:read` and `findings:read`. Polling runs no faster than every five seconds. Results are read using the uploaded analysis ID and every findings cursor, including after an empty page. Counts include all returned workflow statuses.

`fail-on: high` fails on high or critical findings; `medium` includes medium and above, and `low` includes every scored severity. `none` disables this severity gate. Findings labelled `unknown` or `none` are counted separately and never trigger a severity threshold.

When waiting, matching coverage must be explicitly complete (`match_partial: false`). True, null or a missing value stops the build even with zero findings. The original script's intentional override remains available as the environment variable `CRACKEN_ALLOW_PARTIAL_FINDINGS=1`; use it only when you accept incomplete coverage. It does not disable the severity gate. A successful analysis and zero findings are not proof of security or compliance.

| Exit code | Meaning |
|---|---|
| `0` | Upload accepted without waiting, or analysis succeeded with readable findings and policy passed |
| `1` | Configuration, network, HTTP or malformed-response error |
| `2` | Analysis failed, or final `accepted` archive has no analysis |
| `3` | Findings reached the configured severity threshold |
| `4` | Timeout |
| `5` | Matching coverage incomplete or unconfirmed |

## GitLab, Bitbucket and Azure

Use [gitlab/cracken.gitlab-ci.yml](gitlab/cracken.gitlab-ci.yml) via `include: project:` from an access-controlled GitLab mirror. Pin the include to a full commit SHA and extend `.cracken-upload`, as shown in [examples/gitlab.yml](examples/gitlab.yml). GitLab `include: remote:` needs an anonymously readable HTTPS copy; it cannot directly include this private GitHub repository.

The job downloads the same upload script from GitHub at `CRACKEN_ACTION_SHA` and verifies it against `CRACKEN_SCRIPT_SHA256` before execution. Set both pins from the reviewed commit:

```sh
git rev-parse HEAD
shasum -a 256 scripts/upload.sh
```

Provide a separate masked `CRACKEN_REPO_TOKEN` with read-only repository contents access for that private download, and a masked/protected `CRACKEN_API_KEY` for uploads. Never reuse the API key as a GitHub repository credential. The runner needs the upload dependencies plus `sha256sum` or `shasum` for the template's checksum verification. Make your SBOM available as a build artifact.

[Bitbucket](examples/bitbucket.yml) and [Azure Pipelines](examples/azure.yml) snippets call a reviewed copy of `scripts/upload.sh` vendored as `ci/cracken-upload.sh` in your consuming repository. Record its source commit and SHA-256 when copying it. These snippets are neither a Bitbucket pipe nor an Azure Marketplace extension.

## Generate the SBOM in CI (syft)

Generation runs inside the customer's CI. Source code stays there; only the generated SBOM is uploaded through the existing crAcken API. Licences are declared licences from package metadata as syft reports them, without a file-level licence scan. This feature does not run grype or produce VEX. Review the inventory before uploading: package metadata can reveal internal information.

GitHub example (after checkout):

```yaml
- uses: alexv-mc2/cracken-action@REPLACE_WITH_FULL_COMMIT_SHA
  id: cracken
  with:
    api-url: https://<your-crAcken-API-host>/functions/v1/api-v1
    api-token: ${{ secrets.CRACKEN_API_KEY }}
    project: ${{ vars.CRACKEN_PROJECT_ID }}
    release: ${{ github.sha }}
    generate: syft
    syft-version: '1.55.0'
    scan-path: .
# A later artifact step can archive ${{ steps.cracken.outputs.sbom-path }}.
```

Do not set `sbom-file` together with `generate: syft`. The generator scans `dir:<scan-path>`, excludes `./.git`, and sets the source name and version from `GITHUB_REPOSITORY` / `GITHUB_SHA` or `CI_PROJECT_PATH` / `CI_COMMIT_SHA` when available. It writes CycloneDX JSON to a private temporary directory, then passes that exact file to the unchanged upload script. SBOM content is never printed. The generated file remains available until the runner removes its temporary files; archive it during the same job.

GitLab example (use an access-controlled mirror of this repository):

```yaml
include:
  - project: your-group/cracken-action
    ref: REPLACE_WITH_FULL_COMMIT_SHA
    file: /gitlab/cracken.gitlab-ci.yml

generate-and-upload-sbom:
  extends: .cracken-upload
  variables:
    CRACKEN_ACTION_SHA: REPLACE_WITH_FULL_COMMIT_SHA
    CRACKEN_SCRIPT_SHA256: REPLACE_WITH_UPLOAD_SCRIPT_SHA256
    CRACKEN_GENERATE_SCRIPT_SHA256: REPLACE_WITH_GENERATE_SCRIPT_SHA256
    CRACKEN_PROJECT_ID: REPLACE_WITH_PRODUCT_UUID
    CRACKEN_GENERATE: syft
    SYFT_VERSION: '1.55.0'
    SCAN_PATH: .
    CRACKEN_SBOM_PATH_FILE: '$CI_PROJECT_DIR/cracken-sbom-path.txt'
  after_script:
    - cp "$(cat cracken-sbom-path.txt)" generated-sbom.cdx.json
  artifacts:
    paths: [generated-sbom.cdx.json]
```

Set masked `CRACKEN_API_KEY` and `CRACKEN_REPO_TOKEN` secrets and the `CRACKEN_API_URL` variable as for upload mode. Set the generator script pin from `shasum -a 256 scripts/generate-syft.sh` at the same reviewed commit. `CRACKEN_SBOM_PATH_FILE` optionally records the generated path for a later GitLab artifact step; it contains a path, not SBOM content. See both variants in [examples/github.yml](examples/github.yml) and [examples/gitlab.yml](examples/gitlab.yml).

The default syft **1.55.0** was verified as the latest stable release through the [official GitHub release API](https://api.github.com/repos/anchore/syft/releases/latest) on 2026-10-29; [v1.55.0](https://github.com/anchore/syft/releases/tag/v1.55.0) was published on 2026-10-19. Its `syft_1.55.0_checksums.txt` SHA-256 is pinned in this repository:

```text
aba5ac8ee870bb93fd3b2058471ffe7e57492ba673b5e0bcbfca92006c2f4dc7
```

On Linux or macOS (`amd64` / `arm64`), an existing `syft` is reused only when its reported version exactly matches the pin. Otherwise the official release tarball and checksums file are downloaded from `anchore/syft` releases. The checksums file must match the repository pin, and the tarball must match its entry before extraction. Other platforms fail clearly; installation never uses `curl | sh`.

A non-default `syft-version` without a repository checksum pin fails, including when that version is already on PATH. `syft-insecure-skip-pin: 'true'` (GitLab: `SYFT_INSECURE_SKIP_PIN: 'true'`) explicitly permits it. For a downloaded custom version, the tarball is still checked against the release checksums, but an attacker who replaces both assets could bypass that check. The override does not disable the pinned checksums-file verification for the default version. Prefer the default verified pin.

Syft is licensed under Apache-2.0 and downloaded at run time from [anchore/syft releases](https://github.com/anchore/syft/releases). Its code is not vendored; see [NOTICE](NOTICE).

## Generate with cracken-sbom, then upload

First install and verify a pinned [cracken-sbom](https://github.com/alexv-mc2/cracken-sbom) release and its pinned Syft engine using the generator's [verification instructions](https://github.com/alexv-mc2/cracken-sbom/blob/main/docs/VERIFICATION.md). For this separate workflow, install the tools yourself. For example, with verified tools already available and an unpacked root filesystem:

```sh
# Step 1: generate locally; the output directory must be new.
./cracken-sbom generate \
  --target-type rootfs --target /work/firmware/rootfs \
  --target-id firmware-1.2.3 --syft /opt/verified-tools/syft \
  --output /work/evidence/firmware-1.2.3

# Step 2: upload only the SBOM, with credentials supplied by the CI secret manager.
export CRACKEN_API_URL='https://<your-crAcken-API-host>/functions/v1/api-v1'
export CRACKEN_PROJECT_ID='00000000-0000-0000-0000-000000000000'
export VERSION=1.2.3 SBOM_FILE=/work/evidence/firmware-1.2.3/sbom.cdx.json
WAIT=true FAIL_ON=high sh scripts/upload.sh
```

Keep `provenance.json` and `quality.json` in your own environment. Review the generated inventory before uploading; package names can reveal internal information. In a GitHub workflow, the second step can instead be the Action shown above.

## Security and limits

Use HTTPS. HTTP is allowed only for loopback tests (`localhost`, `127.0.0.1`, `[::1]`). URLs must not contain credentials, queries or fragments. The upload script does not follow redirects; official syft release downloads follow HTTPS redirects to GitHub asset storage. It disables shell tracing and passes the bearer header to curl over standard input, keeping it out of curl's command arguments. Do not trace or print secrets in your surrounding CI steps. API error messages are screened for API key text before logging.

Send **one uncompressed JSON object**, supported as CycloneDX JSON, SPDX 2 JSON or SPDX 3 JSON-LD, at most **10 MiB (10,485,760 bytes)** including whitespace and an optional UTF-8 BOM. The script checks raw bytes before sending. XML, SPDX tag-value and ZIP/gzip bodies are not supported. The database's 16 MiB stored SPDX 3 ceiling does not increase the API upload allowance. Oversized requests receive HTTP 413 `payload_too_large`; a timeout is not proof of a received 413. The client uses a 120-second per-request ceiling, bounded by the remaining configured timeout.

API write limits are 10 requests/minute per key, 20/minute and 200/day per company. The inherited curl retry behavior retries transient errors with the same idempotency key. Use a dedicated service account with only required scopes, rotate expiring keys and revoke exposed keys immediately.

## Versioning and local checks

Pin the Action, template and script to reviewed full commit SHAs. A moving `v1` compatibility tag will be introduced later; it is not created by this work. This repository currently remains private. Publication and API rollout are separate operator actions.

Run the local fake-API suite without real credentials or an external API:

```sh
shellcheck scripts/*.sh tests/*.sh # if installed
bash tests/test-upload.sh
bash tests/test-generate.sh
python3 -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' action.yml gitlab/cracken.gitlab-ci.yml examples/*.yml
# If installed: actionlint examples/github.yml
```

Tests require Bash and Python 3 in addition to the upload dependencies; the YAML check needs PyYAML. There are no TypeScript sources or TypeScript typecheck in this shell/Python repository. There are no repository workflows that run on GitHub-hosted runners.

## License and reuse

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The upload logic comes from crAcken's own API CI example. DependencyTrack/gh-upload-sbom informed input naming only; no implementation code was copied from it.
