# Setup and security

## Trial installation

1. Install Sunfish Codex Isolated from the Sunfish Home Assistant Apps repository.
2. Set `allowed_user_id` to the intended Home Assistant owner's exact user ID. Empty or invalid values fail closed. Menu visibility alone does not provide authorization.
3. Optionally enter the existing HA-MCP endpoint in the password-type `mcp_url` field. Never paste it into chat, Git or the coding workspace.
4. Keep automatic updates off and boot manual during acceptance testing.
5. Start the App and inspect the non-sensitive readiness log. If sandbox or access checks fail, stop; do not enable full access, add SYS_ADMIN, disable AppArmor or expose a host port.
6. Open the web UI while signed in as the allowed Home Assistant user. Other users and requests without a trusted Ingress identity are denied.
7. Personally complete the ChatGPT device-code sign-in shown by Codex. Do not share the one-time code or cached authentication file. Device-code authentication may first need enabling in personal ChatGPT Security settings or workspace admin permissions.
8. Test a simple read-only HA query. Write tools are excluded from discovery and rejected by the relay. The trial does not grant permission to expand this policy.

## Scope

Only this App's persistent `/data` workspace is explicitly requested. No HA configuration, other Apps' files, media, backups, Docker socket, hardware devices or host namespaces are requested. Supervisor provides standard container mounts, including a read-only `/dev` view, and its standard seccomp policy; an empty App device list is not a claim that `/dev` does not exist. Codex runs as UID/GID1000; initialization and the credential-holding relay run as container root without host grants. The relay and terminal backend listen on container loopback. The Ingress proxy accepts only HA's documented proxy source and the configured user's trusted identity.

The default Docker AppArmor profile may deny the mounts required by bwrap. Startup deliberately fails closed in that case. This trial does not disable AppArmor or add a custom relaxed profile or SYS_ADMIN. A failed readiness check is an installation blocker requiring a separately reviewed solution, not permission to remove the check.

The read-only HA tool policy covers search, states, history, entity/device/exposure metadata, overview, labels, zones and Home Assistant best-practice skill documents. It does not expose service calls, configuration writes, Apps, logs or integration options. Editing Codex configuration cannot lift the root relay's allowlist.

Read-only HA access is not network isolation. Code can still make outbound network requests and access its own ChatGPT authentication cache. Keep secrets out of the coding workspace. `/data/options.json` is root-only and must never be logged. Password fields mask the UI but do not mean encrypted on-disk options. Treat App backups and `/data/home/.codex/auth.json` as credentials. Protect backups and keep the recovery key separately.

## Supply chain

Codex and bwrap are downloaded only from the official `openai/codex` release `rust-v0.160.0`. `build_download.py` verifies hard-coded SHA-256 digests, exact archive members and amd64 ELF headers before installing the files. No remote installer script is executed. The build runs `codex --version` and records installed Alpine package versions. Transitive packages are not fully locked, and independent Sigstore bundle verification is not claimed.

## Recovery

Stopping this App has no Home Assistant automation or device effect. It does not restart Home Assistant or Zigbee2MQTT. To remove the trial, stop it and explicitly approve uninstalling only this App; uninstall may delete its workspace and authentication cache. Revoke the Codex session separately if credentials might have been copied. Do not restore the entire Home Assistant instance to undo this App installation.

This terminal is not the ChatGPT website or desktop App, and it does not automatically inherit a desktop chat's full history.

## Primary references

- [Official Codex authentication](https://learn.chatgpt.com/docs/auth)
- [Codex Linux sandbox](https://learn.chatgpt.com/docs/sandboxing)
- [Home Assistant Ingress](https://developers.home-assistant.io/docs/apps/presentation/)
- [Home Assistant App configuration](https://developers.home-assistant.io/docs/apps/configuration/)
- [Official pinned Codex release](https://github.com/openai/codex/releases/tag/rust-v0.160.0)
