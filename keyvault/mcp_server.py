"""MCP server: lets an agent *use* credentials without ever receiving them.

Tools: list_credentials (metadata only) and http_request (secret attached server-side).
There is deliberately no tool that returns a secret value.

mcp 2.x note: only ToolError text is shown to the model; any other exception is masked and logged
server-side, which is a useful safety net for a tool that handles secrets.
"""
from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .proxy import MAX_BODY_BYTES, ProxyError, send
from .vault import VaultError, VaultHandle

INSTRUCTIONS = (
    "Use list_credentials to see which API credentials you may use, then http_request to call an API "
    "with one. You never see secret values: keyvault attaches them to the request itself. Only the "
    "listed hosts and methods work, redirects are not followed, and large responses are truncated."
)


def build_server(handle: VaultHandle, allow: set | None = None, max_bytes: int = MAX_BODY_BYTES) -> MCPServer:
    mcp = MCPServer("keyvault", instructions=INSTRUCTIONS)

    def visible() -> dict:
        try:
            vault = handle.current()
        except VaultError as e:
            raise ToolError(str(e)) from None
        # Env-only (kind=none) credentials and anything outside --allow are invisible to the agent.
        return {
            n: c for n, c in vault.creds.items()
            if c.kind != "none" and (allow is None or n in allow)
        }

    @mcp.tool()
    def list_credentials() -> list[dict]:
        """List the API credentials this server may use: name, provider, allowed hosts, enabled HTTP
        methods, tags. Secret values are never returned."""
        return [c.agent_view() for _, c in sorted(visible().items())]

    @mcp.tool()
    async def http_request(
        credential: str,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        json_body: Any = None,
        body: str | None = None,
        timeout_seconds: float = 30,
    ) -> dict:
        """Call an HTTPS API using a stored credential. Pass the credential's NAME; keyvault attaches the
        secret itself, so you never see or handle it.

        Rules: the URL host must be one of the credential's allowed hosts (see list_credentials); only
        the methods listed for that credential are permitted (default GET/HEAD); redirects are NOT
        followed (the 3xx and its Location header are returned; call again if you want to follow);
        do not set Authorization or API-key headers yourself. Responses are text-only, size-capped,
        and any echo of the secret is redacted.

        Args:
            credential: credential name from list_credentials
            method: HTTP method, e.g. GET or POST
            url: absolute https URL
            headers: extra non-auth request headers
            params: query parameters to append
            json_body: JSON request body (mutually exclusive with body)
            body: raw text request body
            timeout_seconds: 1 to 120
        """
        cred = visible().get(credential)
        if cred is None:
            raise ToolError(f"unknown credential '{credential}'. Call list_credentials to see what is available.")
        try:
            return await send(
                cred, method=method, url=url, headers=headers, params=params,
                json_body=json_body, body=body, timeout=timeout_seconds, max_bytes=max_bytes,
            )
        except ProxyError as e:
            raise ToolError(str(e)) from None

    return mcp
