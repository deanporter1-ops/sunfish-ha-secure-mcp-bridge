"""Pure ingress-policy generation. Never accept identity from an arbitrary peer."""

import re

USER_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
USER_ID_TOKEN = "__ALLOWED_USER_ID__"


def validate_user_id(value):
    if not isinstance(value, str) or USER_ID.fullmatch(value) is None:
        raise ValueError("A valid allowed_user_id is required before starting")
    return value


def identity_allowed(header, configured_id):
    """Offline counterpart to nginx's case-sensitive, fully anchored regex."""
    validate_user_id(configured_id)
    return isinstance(header, str) and header == configured_id


def render_nginx_config(template, configured_id):
    configured_id = validate_user_id(configured_id)
    if template.count(USER_ID_TOKEN) != 1:
        raise ValueError("Unexpected ingress configuration template")
    return template.replace(USER_ID_TOKEN, configured_id)
