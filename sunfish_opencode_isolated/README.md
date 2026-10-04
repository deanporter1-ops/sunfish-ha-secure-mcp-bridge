# Sunfish OpenCode read-only trial — local candidate

Dean approved installation of this isolated OpenCode + Big Pickle fallback and
its free-period cloud data-use/privacy implications on 2026-10-04. The previous
Codex app has been removed after its native sandbox failed the unchanged HA
container restrictions; no isolation settings were relaxed to make it run.

This directory is still a local candidate: it has not yet been Linux-built or
installed. Approval is not a successful deployment or runtime acceptance test.
Publication, installation, and live acceptance remain separate steps after the
final source review. Local tests make no live HA requests or model prompts.

OpenCode is pinned to `1.18.34`. Both normal and small-model work select only
`opencode/big-pickle`; every other provider and model is excluded. No paid API key,
account login, billing setup, or cloud prompt is created by these files.

## Approved privacy decision and continuing limits

Big Pickle is currently free for a limited period. OpenCode's official Zen privacy
notice says data collected during this period may be used to improve the model.
An HA review can disclose presence, device names, temperatures, and history to
that remote provider. Read-only access does not make those data non-private.
Dean has approved these privacy implications for the requested read-only trial.
This does not authorize a paid provider, broader device control, or publishing
household data, credentials, or private endpoint URLs.
Free availability and pricing are not permanent guarantees. No fallback to a paid
provider is configured; unavailable models must fail rather than widen the allowlist.

[Official pricing and privacy notice](https://opencode.ai/docs/zen/)

## Boundaries

- HA access passes through the separate root process's loopback MCP relay. Its
  hard ten-tool allowlist is authoritative, even if application permissions change.
- The upstream MCP URL is a root-only app option. It is not written into OpenCode
  config, its environment, or a terminal banner.
- OpenCode runs as UID/GID 1000. It has no HA, host, Docker, or Supervisor mounts
  or API permission. Default AppArmor must remain enabled.
- The owner-ID ingress gate and Supervisor-source gate remain mandatory.
- Application tools default to denied; only the ten specifically named MCP
  tools are allowed. Bash, edits, subagents, external directories, web tools,
  skills, and MCP resource tools are not allowed by the agent policy.
- OpenCode does not provide the Codex native workspace sandbox. These application
  permissions must not be described as an OS sandbox or as protection against
  arbitrary code running under UID 1000.

## Runtime contract

`runtime_config.py` defines public config and a clean environment. Initialization
must precreate its `ROOT_DIRECTORIES` as root-owned, non-user-writable directories
and `USER_DIRECTORIES` as UID/GID 1000 writable. The passwd home should match the
root-controlled `HOME`. `/data/options.json` must be root-owned mode `0600`.
Initialization writes `/etc/opencode/opencode.json` as root using protected,
symlink-rejecting startup-only writes and sets mode `0644` (no secret exists in
it). These are truncating writes, not atomic replacements. They run before the
terminal or MCP relay starts. Keep the parent directory root-owned `0755`.
Do not place another `opencode.jsonc` there: that file loads afterward.

The root-controlled home and XDG config directories prevent persisted user
`.opencode` plugins/custom tools from being automatically imported. Data/cache/
state remain writable in app-specific `/data/opencode` paths. Project config,
default plugins, external plugins, automatic updates, sharing, external skills,
LSP downloads, and live model-catalog refresh are disabled.

Startup readiness must pass before the terminal or MCP relay starts. The pinned
native binary lists its embedded catalog using fresh temporary `/run` data,
cache, state, and temporary directories; saved authentication, account settings,
and an old model catalog cannot substitute for that proof. Model fetching and
refresh are disabled, and only `opencode/big-pickle` may appear. Native `debug
config` output must then exactly match the version-specific deny-all/no-MCP
configuration, followed by the final ten-tool loopback configuration while the
relay is still stopped. The checks validate exact types and ordered permissions
and reject extra providers, credentials, agents, plugins, or tool permissions.
They use no login, prompt, model inference, or live HA request and log only fixed
non-sensitive pass/failure categories. Any failed check stops startup.

The launch wrapper starts no login or prompt and exposes no standalone OpenCode
network listener. Opening the terminal is not a cloud inference test. Do not
relax AppArmor or mount permissions to make a failed readiness check pass.

## Offline verification

Run `python -m unittest discover -s tests -v` from this directory. Tests use local
objects/fake servers only, never live HA or a cloud model. Python syntax checking
and `bash -n opencode-session` are additional local checks. These do not prove a
container build, HA ingress behavior, model availability, or physical controls.

## Version-matched primary sources

- [V1 config schema](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/core/src/v1/config/config.ts)
- [Provider whitelist and no-key public free-model path](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/provider/provider.ts)
- [Remote MCP schema](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/core/src/v1/config/mcp.ts)
- [Permission evaluation](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/permission/index.ts)
- [MCP permission naming](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/mcp/catalog.ts)
- [Linux managed-config location](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/config/managed.ts)
- [Config merge precedence](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/config/config.ts)
- [Plugin isolation flags](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/plugin/index.ts)
- [Runtime flags](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/effect/runtime-flags.ts)
- [Sharing disable flag](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/share/share-next.ts)
- [CLI arguments](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/cli/cmd/tui.ts)
- [Offline model-catalog command](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/cli/cmd/models.ts)
- [Disk-cache versus embedded-catalog precedence](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/core/src/models-dev.ts)
- [Native resolved-config command](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/opencode/src/cli/cmd/debug/config.ts)
- [Agent config normalization](https://raw.githubusercontent.com/anomalyco/opencode/v1.18.34/packages/core/src/v1/config/agent.ts)
