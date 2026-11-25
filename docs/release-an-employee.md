# Release an Employee from Your Repository

This guide shows how to release a Seren Employee from a Git repository using CI or a laptop.

Instead of storing a personal API key in CI, your organization approves a **release source**. When a CI run releases an Employee, it proves which source it is and gets a 30-minute **release pass**. With GitHub Actions, GitLab, and CircleCI, no long-lived secret is stored in CI.

## What a Release Source Is

A **release source** is a trusted place that can upload bundles, run test runs, list uploads, and release a named list of Employees for your organization.

There are two kinds of release source:

- **Signed-run source:** a repository and branch in GitHub Actions, GitLab, or CircleCI (with an optional deployment environment for GitHub Actions or GitLab). The CI signs an OpenID Connect identity token for each run.
- **Organization release key:** a short-lived key (`serenrk_...`) that lives 1 to 30 days, for a CI system that cannot sign its runs.

Key rules:

- **Who can approve, edit, or revoke a source:** a built-in **Owner** or **Admin** of the publishing organization, using a signed-in browser session (in the Console, in the CLI after browser login, or in hosted MCP for signed-run sources). API keys cannot approve, edit, or revoke release sources, and cannot create release keys.
- **Owned by the organization:** a release source belongs to your organization, not to an individual account. It keeps working if the person who approved it later leaves.
- **Named Employee list:** each source lists the exact Employee slugs it may release. Add a new Employee's slug to a source's list before its first release.
- **Permanent repository identity:** you enter the repository name when approving a signed-run source. Seren records the repository's permanent ID on the first matching signed run and requires that ID on future runs. A renamed or transferred repository keeps releasing; a different repository that later takes the old name cannot.

## Approve a Release Source

### In the Console

1. Open **Employees you publish** at <https://console.serendb.com/published-employees>.
2. In **Release sources**, select **Approve a repository**.
3. Choose the CI product (**GitHub Actions**, **GitLab**, or **CircleCI**).
4. Enter:
   - **Label:** a name to recognize this source.
   - **Repository:** the repository name in your CI product's format (see the table below).
   - **Branch:** the branch name only, such as `main` (never `refs/heads/main`).
   - **Environment (optional):** for GitHub Actions or GitLab, require runs to come from a named CI environment.
   - **Signing address (issuer):** optional for self-hosted GitLab; required for CircleCI (`https://oidc.circleci.com/org/<circleci-org-id>`).
   - **Employees:** the Employee slugs this source may release.
5. Select **Approve repository**.

### With the CLI

First sign in with browser login (choose browser login, not an API key):

```bash
seren auth login
```

Then approve a signed-run source for your CI product. Repeat `--template <slug>` for each Employee the source may release.

**GitHub Actions:**

```bash
seren agent managed-release-sources <organization-id> approve \
  --product github-actions \
  --repository <owner>/<repo> \
  --branch main \
  --label "GitHub main" \
  --template <employee-slug>
```

Add `--environment <name>` to require a GitHub Actions deployment environment.

**GitLab:**

```bash
seren agent managed-release-sources <organization-id> approve \
  --product gitlab \
  --repository <group>/<project> \
  --branch main \
  --label "GitLab main" \
  --template <employee-slug>
```

GitLab defaults to `https://gitlab.com`. For a self-hosted GitLab instance reachable over public HTTPS, pass `--issuer https://gitlab.example.com` (the `https://` origin with no path, query, or fragment). Add `--environment <name>` to require a GitLab environment. Self-hosted GitLab on a private network cannot be reached to read its signing keys; use a [release key](#ci-that-cannot-sign-use-a-release-key) instead.

**CircleCI:**

```bash
seren agent managed-release-sources <organization-id> approve \
  --product circleci \
  --issuer https://oidc.circleci.com/org/<circleci-org-id> \
  --repository github.com/<org>/<repo> \
  --branch main \
  --label "CircleCI main" \
  --template <employee-slug>
```

CircleCI requires `--issuer https://oidc.circleci.com/org/<circleci-org-id>` (using your CircleCI organization UUID) and writes `--repository` as `<host>/<org>/<repo>`, such as `github.com/<org>/<repo>`. CircleCI tokens have no environment claim.

**List, edit, or revoke sources:**

```bash
seren agent managed-release-sources <organization-id> list

# Updates only supplied fields; --template replaces the full Employee list
seren agent managed-release-sources <organization-id> edit <release-source-id> \
  --branch main \
  --template <employee-slug>

# Remove an environment requirement
seren agent managed-release-sources <organization-id> edit <release-source-id> \
  --clear-environment

# Revoke a source (stops its passes immediately and cancels its pending held releases)
seren agent managed-release-sources <organization-id> revoke <release-source-id>
```

### Signed-Run Addresses and Claims

Every CI token must be signed with RS256 and addressed to audience (`aud`) `https://api.serendb.com`. Seren verifies the token against the OpenID discovery document at `<signing-address>/.well-known/openid-configuration` and checks these claims:

| CI product | `--product` | Signing address (`iss`) | Repository format and claim | Permanent ID claim | Branch claim | Environment claim |
|---|---|---|---|---|---|---|
| GitHub Actions | `github-actions` | `https://token.actions.githubusercontent.com` | `<owner>/<repo>` (`repository`) | `repository_id` | `ref` (`refs/heads/<branch>`) | `environment` (optional) |
| GitLab | `gitlab` | `https://gitlab.com` or your `https://` instance origin | `<group>/<project>` (`project_path`) | `project_id` | `ref_path` (`refs/heads/<branch>`) | `environment` (optional) |
| CircleCI | `circleci` | `https://oidc.circleci.com/org/<circleci-org-id>` | `<host>/<org>/<repo>`, e.g. `github.com/<org>/<repo>` (`oidc.circleci.com/vcs-origin`) | `oidc.circleci.com/project-id` | `oidc.circleci.com/vcs-ref` (`refs/heads/<branch>`) | None |

## Copy-Ready CI Pipelines

Each pipeline below downloads the pre-built `seren-x86_64-unknown-linux-musl` binary and `SHA256SUMS.txt` from Seren CLI release `v0.16.0`, checks the binary with `sha256sum --check --ignore-missing`, and runs `seren agent managed-release`.

Replace `<organization-id>` with your Seren organization ID and `./my-employee` with the path to your Employee folder containing `seren-release.json`.

### GitHub Actions

Save as `.github/workflows/release-employee.yml`. No secrets are needed.

```yaml
name: Release Employee

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  release:
    runs-on: ubuntu-latest
    env:
      SEREN_ORGANIZATION_ID: "<organization-id>"
      SEREN_CLI_VERSION: "v0.16.0"
    steps:
      - uses: actions/checkout@v4

      - name: Release Employee
        run: |
          set -eu
          bin_dir=$(mktemp -d)
          trap 'rm -rf "$bin_dir"' EXIT
          (
            cd "$bin_dir"
            curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/seren-x86_64-unknown-linux-musl"
            curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/SHA256SUMS.txt"
            sha256sum --check --ignore-missing SHA256SUMS.txt
            chmod +x seren-x86_64-unknown-linux-musl
          )
          "$bin_dir/seren-x86_64-unknown-linux-musl" agent managed-release "$SEREN_ORGANIZATION_ID" ./my-employee
```

How it works:

- `permissions: id-token: write` lets the job request a signed token from `$ACTIONS_ID_TOKEN_REQUEST_URL` using `$ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
- The CLI requests that token with `audience=https://api.serendb.com` and trades it for a release pass.
- If `id-token: write` is missing, the step fails without publishing anything.
- If your approved source specifies an environment, add `environment: <environment-name>` to the `release` job.

### GitLab

Add this job to `.gitlab-ci.yml`. No secrets are needed.

```yaml
release-employee:
  image: buildpack-deps:bookworm-scm
  variables:
    SEREN_ORGANIZATION_ID: "<organization-id>"
    SEREN_CLI_VERSION: "v0.16.0"
  id_tokens:
    SEREN_RELEASE_ID_TOKEN:
      aud: https://api.serendb.com
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  script:
    - |
      set -eu
      bin_dir=$(mktemp -d)
      trap 'rm -rf "$bin_dir"' EXIT
      (
        cd "$bin_dir"
        curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/seren-x86_64-unknown-linux-musl"
        curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/SHA256SUMS.txt"
        sha256sum --check --ignore-missing SHA256SUMS.txt
        chmod +x seren-x86_64-unknown-linux-musl
      )
      "$bin_dir/seren-x86_64-unknown-linux-musl" agent managed-release "$SEREN_ORGANIZATION_ID" ./my-employee
```

How it works:

- `id_tokens` gives the job `SEREN_RELEASE_ID_TOKEN` addressed to `https://api.serendb.com`.
- The CLI reads `SEREN_RELEASE_ID_TOKEN` automatically and trades it for a release pass.
- If your approved source specifies a GitLab environment, add `environment: <environment-name>` to the job.

### CircleCI

Add this job to `.circleci/config.yml`. No secrets are needed.

When approving the source in Seren, set `--repository` to `github.com/<org>/<repo>` (or `<host>/<org>/<repo>` without `https://`) and `--issuer` to `https://oidc.circleci.com/org/<circleci-org-id>`.

```yaml
version: 2.1

jobs:
  release-employee:
    docker:
      - image: cimg/base:current
    environment:
      SEREN_ORGANIZATION_ID: "<organization-id>"
      SEREN_CLI_VERSION: "v0.16.0"
    steps:
      - checkout
      - run:
          name: Release Employee
          command: |
            set -eu
            export SEREN_RELEASE_ID_TOKEN=$(circleci run oidc get --claims '{"aud": "https://api.serendb.com"}')
            test -n "$SEREN_RELEASE_ID_TOKEN"
            bin_dir=$(mktemp -d)
            trap 'rm -rf "$bin_dir"' EXIT
            (
              cd "$bin_dir"
              curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/seren-x86_64-unknown-linux-musl"
              curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/SHA256SUMS.txt"
              sha256sum --check --ignore-missing SHA256SUMS.txt
              chmod +x seren-x86_64-unknown-linux-musl
            )
            "$bin_dir/seren-x86_64-unknown-linux-musl" agent managed-release "$SEREN_ORGANIZATION_ID" ./my-employee

workflows:
  release:
    jobs:
      - release-employee:
          filters:
            branches:
              only: main
```

How it works:

- CircleCI's default OIDC token is addressed to your CircleCI organization ID, and V3 tokens omit the repository and branch claims.
- `circleci run oidc get --claims '{"aud": "https://api.serendb.com"}'` returns a V2 token carrying `oidc.circleci.com/vcs-origin`, `oidc.circleci.com/project-id`, and `oidc.circleci.com/vcs-ref`, addressed to `https://api.serendb.com`.
- The CLI reads `SEREN_RELEASE_ID_TOKEN` and trades it for a release pass.

### Using Your Own Release Script

If your team packages and uploads bundles with its own script, you can still use the CLI to obtain a 30-minute pass:

```bash
PASS=$(seren agent managed-release-pass <organization-id>)
```

`managed-release-pass` prints only the pass on standard output and writes which proof it used to standard error. Pass `-o json` for the full JSON response.

## CI That Cannot Sign: Use a Release Key

If your CI product cannot issue OpenID signed run tokens, or if you run a self-hosted GitLab instance on a private network, create an **organization release key**.

### 1. Create a Release Key

Only an Owner or Admin with a signed-in browser session can create a release key. A release key lives 1 to 30 days.

**In the Console:** open <https://console.serendb.com/published-employees>, go to **Release sources**, and select **Create a release key**.

**In the CLI (after `seren auth login` with browser login):**

```bash
seren agent managed-release-sources <organization-id> create-key \
  --label "CI release key" \
  --days 30 \
  --template <employee-slug>
```

The CLI prints the key once (`serenrk_...`) with the notice `Store it now. Seren will not show it again.`

MCP does not provide a tool to create release keys so the key text never passes through an assistant conversation.

### 2. Store and Run in CI

Store the key as a masked secret environment variable named `SEREN_RELEASE_KEY` in your CI. Replace `<organization-id>` with your Seren organization ID and `./my-employee` with your Employee folder, then download, verify, and run the CLI:

```bash
set -eu
SEREN_ORGANIZATION_ID="<organization-id>"
SEREN_CLI_VERSION="v0.16.0"
bin_dir=$(mktemp -d)
trap 'rm -rf "$bin_dir"' EXIT
(
  cd "$bin_dir"
  curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/seren-x86_64-unknown-linux-musl"
  curl -fsSLO "https://github.com/serenorg/seren/releases/download/${SEREN_CLI_VERSION}/SHA256SUMS.txt"
  sha256sum --check --ignore-missing SHA256SUMS.txt
  chmod +x seren-x86_64-unknown-linux-musl
)
"$bin_dir/seren-x86_64-unknown-linux-musl" agent managed-release "$SEREN_ORGANIZATION_ID" ./my-employee
```

The CLI exchanges `SEREN_RELEASE_KEY` for a 30-minute release pass and uses the pass (never the key) to upload and release.

### 3. Replace Before It Expires

Owners and Admins receive an email 3 days before a release key expires. To rotate with no downtime:

1. Create a new release key for the same Employees (old and new keys can overlap).
2. Update `SEREN_RELEASE_KEY` in your CI.
3. Revoke the old key in the Console or with `seren agent managed-release-sources <organization-id> revoke <release-source-id>`.

## Release from a Laptop

A built-in Owner or Admin can release directly from a laptop with no stored key.

1. Sign in with browser login:

   ```bash
   seren auth login
   ```

   Choose browser login (not an API key).

2. Make sure `SEREN_RELEASE_ID_TOKEN` and `SEREN_RELEASE_KEY` are unset in your shell. The CLI checks proofs in this order:
   1. GitHub Actions signed run (`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`)
   2. `SEREN_RELEASE_ID_TOKEN`
   3. `SEREN_RELEASE_KEY`
   4. Your signed-in browser session

3. Run `managed-release` from your repository:

   ```bash
   seren agent managed-release <organization-id> ./my-employee
   ```

An in-person release pass covers any Employee your organization publishes. Releases made in person are not held: Seren publishes right away, prints `Published <slug> revision <n>.` with any itemized access changes, and records you as having approved them.

## Held Releases and How to Approve Them

### What "Held" Means

When a release comes from a release source (a signed-run source or a release key), Seren compares it with the Employee's current revision:

- **Content-only changes** (edits to instructions, scripts, or assets that do not change what hired copies can reach): publish right away. The CLI prints `Published <slug> revision <n>.` and exits `0`.
- **First release** (the Employee has no current revision yet) or **access changes** (changes to what hired copies can reach, such as network egress hosts, browser permissions, publisher grants, or runtime settings): the release is **held** for approval.

When a release is held:

- Seren stores the exact release request and pins its uploaded bundle.
- Seren emails your organization's Owners and Admins.
- `seren agent managed-release` exits `0` and prints `Held for approval: <reason>.`, each itemized access change, the CLI approval command, and the Console URL (<https://console.serendb.com/published-employees>). With `-o json`, it prints `{"outcome": "held", ...}`.
- Approving a held release publishes the stored release directly. You do not need to rerun CI.

If Seren refuses a release (for example, the Employee slug is not on the source's named list or the source was revoked), the CLI prints Seren's message and exits `1`.

Good to know:

- A newer held release for the same Employee replaces the earlier pending hold.
- An undecided hold lapses after 30 days.
- Revoking a source, or removing an Employee from its list, cancels that source's pending hold for that Employee.
- A release pass can never approve a held release.

### Approve or Refuse a Held Release

Any built-in **Owner** or **Admin** of the publishing organization can approve or refuse a held release using a signed-in session or an unrestricted personal API key.

#### In the Console

1. Open **Employees you publish** at <https://console.serendb.com/published-employees>.
2. Under **Releases waiting for approval**, review the itemized changes.
3. Select **Approve** to publish, or **Refuse** and enter a reason.

#### In the CLI

```bash
# List pending holds with their plain-sentence changes and changes_fingerprint
seren agent managed-held-releases <organization-id> list

# Approve after reviewing the changes and fingerprint
seren agent managed-held-releases <organization-id> approve <held-release-id> \
  --fingerprint <changes-fingerprint>

# Or review interactively and type `yes` when prompted
seren agent managed-held-releases <organization-id> approve <held-release-id>

# Refuse with a note (1 to 2000 characters)
seren agent managed-held-releases <organization-id> refuse <held-release-id> \
  --note "Explain why this release was refused"
```

Omitting `--fingerprint` fetches the pending hold, prints its changes and fingerprint, and prompts for `yes` on an interactive terminal (non-interactive commands must pass `--fingerprint`). If another release lands before you approve and the changes differ, approval is refused (`managed_agent_held_release_changed`) and the CLI prints the updated changes and new fingerprint so you only approve what you have read.

#### In MCP

Ask your MCP-connected assistant to review and decide pending holds using these tools:

- `list_seren_agent_held_releases` — lists held releases, their itemized changes, and `changes_fingerprint`.
- `approve_seren_agent_held_release` — approves a hold; requires `organization_id`, `held_release_id`, and the exact `changes_fingerprint` from the listing you reviewed.
- `refuse_seren_agent_held_release` — refuses a hold with a `note`.

You can also inspect signed-run sources with `list_seren_agent_release_sources`, and manage them in hosted MCP with `approve_seren_agent_release_source`, `update_seren_agent_release_source`, and `revoke_seren_agent_release_source`.

## The `seren-release.json` Settings File

By default, `seren agent managed-release <organization-id> <folder>` reads `<folder>/seren-release.json` (pass `--settings <path>` to read a different file). When the settings file lives inside `<folder>`, the CLI automatically excludes it from the uploaded Employee bundle.

The CLI determines the source commit SHA from `--commit <sha>` or `git -C <folder> rev-parse HEAD` (must be a full 40- or 64-character hexadecimal SHA).

`seren-release.json` rejects unknown fields.

| Field | Required | Default | Description |
|---|---|---|---|
| `slug` | Yes | — | Employee template slug. Must be on the release source's named list when releasing from a source. |
| `display_name` | Yes | — | Employee display name. |
| `deploy_defaults` | Yes | — | Deployment defaults applied to every hired copy (`ManagedAgentTemplateDeployDefaults`). |
| `rollout` | No | `false` | When `true`, offers the published revision to existing hires right away according to each Employer's update settings (the publish request uses a 600-second timeout). When `false`, existing hires pick up the update in the background. |
| `listed` | No | `true` | Initial catalog listing preference when creating a new Employee. New community Employees still wait for Seren review before appearing in the catalog. |
| `release_note` | No | — | Plain-text note (1 to 2000 characters) shown to Employers. |

Required fields inside `deploy_defaults`:

- `mode`: `"cron"` or `"job"` (`"cron"` requires `cron_schedule`; `"job"` refuses `cron_schedule`).
- `model_policy`: `"fast"`, `"balanced"`, or `"deep"`.
- `max_runtime_seconds`: maximum run duration in seconds.
- `browser`: `{"display": "headless" | "headed", "max_session_seconds": <seconds>}` (optional `public_web` and `links` settings).
- `network_egress`: list of allowed egress rules (`{"host": "...", "port": 443, "protocol": "rest" | "tcp" | "sse" | "websocket"}`), or `[]`.
- `script_publisher_grants`: list of publisher grants for skill scripts, or `[]`.

Optional `deploy_defaults` fields include `cron_schedule`, `owner_connection` (`"mail_and_files"`, `"mail_read"`, or `"sign_in_only"`), `hires_per_employer` (`"one"` or `"many"`), `max_tool_output_chars`, `native_tools`, `mcp_tools`, `llm_connection`, `privacy_mode`, `guarded_purchases`, `guarded_submissions`, `cardano_signing`, and `line`.

### Example `seren-release.json`

```json
{
  "slug": "my-employee",
  "display_name": "My Employee",
  "deploy_defaults": {
    "mode": "cron",
    "cron_schedule": "0 9 * * *",
    "model_policy": "balanced",
    "max_runtime_seconds": 300,
    "browser": {
      "display": "headless",
      "max_session_seconds": 60
    },
    "network_egress": [],
    "script_publisher_grants": []
  },
  "rollout": false,
  "listed": true,
  "release_note": "Clarify weekly summary instructions."
}
```

Put your Employee files (`SKILL.md` and any supporting instruction files, scripts, assets, or `requirements.txt`) in the same folder alongside `seren-release.json`. For full command flags and output details, see the [CLI Reference](../cli/README.md#managed-agents).
