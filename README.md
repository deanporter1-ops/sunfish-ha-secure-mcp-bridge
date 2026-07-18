# Sunfish Secure MCP Bridge

A supervised Home Assistant app that connects a private Home Assistant MCP
server to OpenAI Secure MCP Tunnel through a server-side tool and argument
policy.

The app does not publish any host ports or provide an ingress interface. The
OpenAI tunnel client connects outbound over HTTPS; its MCP target is a policy
proxy bound only to container loopback.

No credentials, private endpoints, or Home Assistant configuration are stored
in this repository.

