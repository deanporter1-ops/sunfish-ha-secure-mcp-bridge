# Changelog

## 0.1.4

- Return a clean not-configured response for OAuth discovery paths instead of forwarding them to HA-MCP.

## 0.1.3

- Override the base image entrypoint so the bridge starts directly without invoking s6-overlay `/init`.

## 0.1.2

- Use Home Assistant's maintained default protected AppArmor profile.
- Remove the custom profile that blocked interpreted s6 bootstrap launchers.

## 0.1.1

- Allow the Home Assistant base image shell to read its `/init` launcher.

## 0.1.0

- Initial supervised bridge.
- OpenAI tunnel-client v0.0.10 Linux AMD64, checksum pinned.
- Combined audit and controlled-administration tool profile.
- Argument-level policies for mixed-purpose tools.
- Internal health and readiness endpoints with sanitized logging.
