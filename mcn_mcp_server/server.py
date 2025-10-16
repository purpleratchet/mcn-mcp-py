"""Entry point exposing the MCP server using ``fastmcp``."""

from __future__ import annotations

from fastmcp import FastMCP, Response, oauth

from .config import get_settings
from .mcn_client import McnApiClient
from .oidc import OIDCClient


settings = get_settings()

oidc_client = OIDCClient(
    issuer=str(settings.oidc_issuer),
    client_id=settings.client_id,
    client_secret=settings.client_secret,
    redirect_uri=str(settings.redirect_uri),
    scope=tuple(settings.scope),
    audience=settings.token_audience,
)

mcn_client = McnApiClient(oidc_client=oidc_client)

app = FastMCP("mcn-mcp")


@app.oauth.start()
async def start_oauth(session: oauth.Session) -> oauth.Redirect:
    """Initiate the OAuth redirect flow with MCN."""

    url, state, verifier = await mcn_client.generate_login()
    session["pkce_verifier"] = verifier
    session["oauth_state"] = state
    return oauth.Redirect(url=url, state=state)


@app.oauth.complete()
async def complete_oauth(session: oauth.Session, request: oauth.CallbackRequest) -> oauth.Tokens:
    """Handle the callback coming from the MCN authorization server."""

    verifier = session.get("pkce_verifier")
    expected_state = session.get("oauth_state")
    if verifier is None or expected_state is None:
        raise RuntimeError("OAuth session has expired or is invalid")

    tokens = await mcn_client.complete_login(
        code=request.code,
        code_verifier=verifier,
        state=request.state,
        expected_state=expected_state,
    )
    session["refresh_token"] = tokens.refresh_token
    return oauth.Tokens(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        refresh_token=tokens.refresh_token,
        id_token=tokens.id_token,
        scope=tokens.scope,
    )


@app.oauth.refresh()
async def refresh_oauth(session: oauth.Session) -> oauth.Tokens:
    """Refresh expired access tokens using the stored refresh token."""

    refresh_token = session.get("refresh_token")
    if not refresh_token:
        raise RuntimeError("Cannot refresh tokens without a stored refresh token")
    tokens = await oidc_client.refresh(refresh_token)
    session["refresh_token"] = tokens.refresh_token or refresh_token
    return oauth.Tokens(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        refresh_token=tokens.refresh_token or refresh_token,
        id_token=tokens.id_token,
        scope=tokens.scope,
    )


@app.tool()
async def get_profile() -> Response:
    """Return information about the currently authenticated user."""

    data = await mcn_client.get("users/profile")
    return Response(content=data)


__all__ = ["app"]
