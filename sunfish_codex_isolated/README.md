# Sunfish Codex Isolated

An experimental Home Assistant App for the official OpenAI Codex CLI, with an isolated persistent workspace and a server-enforced read-only Home Assistant MCP relay.

- Authenticated Home Assistant Ingress only; no published host ports.
- An explicit allowed Home Assistant user ID is enforced at the terminal proxy, in addition to the Ingress source-IP check.
- No Home Assistant configuration mounts, host/Docker grants, Supervisor API, or Home Assistant API grant.
- The coding process runs as a non-root user. Startup must pass the Linux sandbox readiness check.
- Official Linux amd64 Codex and bwrap release artifacts are pinned by SHA-256. Base image and direct Alpine packages are pinned.
- Uses personal ChatGPT device-code sign-in; no API key is automatically selected. The model is hosted by OpenAI, not local offline inference.

See DOCS.md for setup, boundaries and limitations. This is a custom Sunfish wrapper, not an official Home Assistant or OpenAI App.
