# Sunfish Secure MCP Bridge

## Options

- **Tunnel ID**: the OpenAI Secure MCP Tunnel identifier.
- **Runtime API key**: enter the scoped runtime key directly here. Never put it
  in logs, chat, or source control.
- **Upstream URL**: the existing private HA-MCP Streamable HTTP endpoint. Treat
  the complete value as a credential.
- **Log level**: `info` or `warn`. Raw HTTP bodies and headers are never logged.

The runtime key is copied to a mode-0600 file on tmpfs before the official
OpenAI client starts. The upstream URL remains in process memory. Home
Assistant stores masked app options in protected app data and may include them
in encrypted backups.

## Network exposure

This app has no ingress and no published ports. Its MCP proxy and the OpenAI
client UI bind to container loopback. Supervisor can reach only the minimal
health endpoint over the internal app network.

## Policy

The single Sunfish profile exposes audit tools and controlled administration.
Destructive deletion, integration or app removal, backup restore, server
restart/shutdown, pairing, reset, and unrestricted service calls are rejected
inside the proxy before reaching Home Assistant.

