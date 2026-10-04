# OpenCode trial operating notes

Dean approved installing the isolated OpenCode + Big Pickle fallback and its
free-period cloud data-use/privacy implications on 2026-10-04. The failed Codex
app has been removed without relaxing HA isolation. This is still a local
candidate, not yet Linux-built or installed; deployment and live acceptance are
not proved by approval or the offline tests.

The approved trial can disclose household readings to the remote model under
Big Pickle's free-period data-use policy. The approval does not cover paid
fallbacks, broader HA control, or publishing private data. Never request or paste
a paid API key, private MCP URL, auth token, or one-time login code into chat.

## Configuration

Initialization owns the root-only `allowed_user_id` and upstream `mcp_url` options.
The existing security module requires an exact lowercase 32-hex-character user
ID. Missing/mismatched identities must fail closed; the owner ID is not logged.
The agent receives only `http://127.0.0.1:8091/mcp`, not the upstream endpoint.

Use the managed JSON produced by `build_runtime_config(enable_mcp=True)` and the
entire fresh dictionary from `build_environment()`, not an inherited environment.
The catalog/initial config probes use `enable_mcp=False`. A final native config
probe checks the intended ten-tool loopback policy before the relay starts; it
cannot access the private upstream endpoint. Never add shell/edit permission or
a second model to recover from a failure.

Do not use `OPENCODE_CONFIG_CONTENT` as a policy-lock substitute: the pinned loader
later merges account configuration and `/etc/opencode` managed files. An explicit
`OPENCODE_CONFIG` loads even earlier. The managed root file has final file-merge
precedence, but app/session-specific controls are not a hard security boundary.
Root-held relay credentials and its server-side allowlist remain decisive.

Keep root `HOME` and XDG config directories read-only to UID 1000. Disabling
project configuration alone still permits discovery in home/global `.opencode`
directories; `OPENCODE_PURE` suppresses external plugins, not independently
discovered JavaScript/TypeScript custom tools. Root directory ownership closes
that persisted-config path for this candidate.

Managed JSON writes are root-protected, symlink-rejecting startup-only truncating
writes, not atomic replacements. They occur before any terminal or relay starts.
The public config stays mode `0644` in root-owned `/etc/opencode` mode `0755`,
while `/data/options.json` remains root-owned mode `0600` and unreadable to the
agent. Never put credentials in the managed JSON, environment, or source.

## Exactly ten allowed HA tools

`ha_search`, `ha_get_state`, `ha_get_history`, `ha_get_entity`, `ha_get_device`,
`ha_get_entity_exposure`, `ha_get_overview`, `ha_config_get_label`, `ha_get_zone`,
`ha_get_skill_guide`.

OpenCode permission names are the server name plus `_` plus the tool name, such as
`sunfish_readonly_ha_search`. Permissions are ordered; default denial comes first
and the exact read-tool exceptions come afterward. The MCP remote schema has no
`enabled_tools` field. Do not use a broad `sunfish_readonly_*` client-side allow.

The relay denies writes, batch requests, subscriptions, and arbitrary resource
reads. Skill resources are narrowly bounded server-side, although the application
policy does not enable its resource-reading tool. Responses scrub known secret
fields, but household readings remain sensitive even after credential redaction.

## Persistence and troubleshooting

Conversations, logs, tool outputs, cache, and state can persist under the app's
`/data/opencode` directory and may be included in backups. The default external
tool-output directory exception is explicitly denied; large output may be
truncated without the agent being able to read the saved full text. Do not imply
full audit coverage when that occurs.

Readiness must verify UID/GID, absent forbidden mounts, root options unreadable
to the agent, exact binary version, ingress syntax, and root config ownership.
It must also run the pinned native model-catalog command with fresh temporary
`/run` XDG data/cache/state and temporary directories, model fetching disabled,
and no saved auth/account/model cache. Only `opencode/big-pickle` may be listed.
Native `debug config` must match both the deny-all/no-MCP policy and the final
ten-tool loopback policy with the relay still stopped. Equality is strict about
types, permissions and their order, and the pinned parser's known derived fields;
extra credentials, providers, plugins, agents, and permissions fail closed.
These checks create no login or model prompt and make no live HA request. Any
readiness failure prevents the terminal and relay from starting.
Use fixed failure categories only. Never log raw configured URLs, options,
subprocess environment, exception text, or credential-bearing stderr.

If the model is unavailable, rate-limited, or the container cannot satisfy these
boundaries, stop and report the limitation. Do not configure a paid fallback,
change AppArmor, add host mounts, expose a new port, or test physical devices.
