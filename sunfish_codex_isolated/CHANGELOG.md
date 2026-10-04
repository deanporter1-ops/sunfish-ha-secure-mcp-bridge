# Changelog

## 0.1.2

- Use explicit Alpine executable paths while retaining the cleaned child environment.
- Distinguish missing executables, process startup errors and timeouts without revealing exception details.

## 0.1.1

- Report fixed, non-sensitive startup diagnostic categories without logging subprocess stderr.

## 0.1.0

Initial isolated Codex trial with pinned official amd64 artifacts, explicit-user Ingress access, startup sandbox checks, non-root workspace and a read-only HA-MCP relay. No HA or host/Docker grants.
