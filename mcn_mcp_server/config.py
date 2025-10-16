"""Configuration models for the MCN MCP server."""

from __future__ import annotations

from functools import lru_cache
from typing import Sequence

from pydantic import Field, HttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables.

    The server requires a registered OAuth client on the MCN identity provider.
    The following environment variables are expected (the ``MCN_`` prefix is
    applied automatically):

    ``CLIENT_ID``
        Public identifier issued when registering the OAuth client.
    ``CLIENT_SECRET``
        Confidential secret used for token exchange. Leave empty for public
        clients that rely on PKCE only.
    ``REDIRECT_URI``
        Callback URL configured for the client registration. This will be used
        both by the MCP server and when generating the authorization URL for
        ChatGPT.
    ``SCOPE``
        Space separated list of scopes requested during the authorization
        redirect. Defaults to ``"openid profile offline_access"`` which grants
        identity information and refresh token access.
    ``OIDC_ISSUER``
        Base URL of the OpenID Connect issuer. The default points to the public
        MCN identity provider.
    """

    model_config = SettingsConfigDict(env_prefix="MCN_", env_file=".env", extra="ignore")

    client_id: str = Field(alias="CLIENT_ID")
    client_secret: str | None = Field(default=None, alias="CLIENT_SECRET")
    redirect_uri: HttpUrl = Field(alias="REDIRECT_URI")
    scope: Sequence[str] = Field(default=("openid", "profile", "offline_access"), alias="SCOPE")
    oidc_issuer: HttpUrl = Field(default="https://base.mcn.ru", alias="OIDC_ISSUER")
    token_audience: str | None = Field(default=None, alias="TOKEN_AUDIENCE")

    @field_validator("scope", mode="before")
    @classmethod
    def _split_scope(cls, value: object) -> Sequence[str]:
        if value is None:
            return ("openid", "profile", "offline_access")
        if isinstance(value, str):
            return tuple(scope for scope in value.split() if scope)
        return value  # type: ignore[return-value]


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings."""

    return Settings()  # type: ignore[arg-type]


__all__ = ["Settings", "get_settings"]
