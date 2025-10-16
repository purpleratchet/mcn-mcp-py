"""OIDC helper utilities used by the MCP server."""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

import httpx
from pydantic import BaseModel, HttpUrl


class OIDCProviderMetadata(BaseModel):
    """Subset of fields returned from the discovery endpoint."""

    issuer: HttpUrl
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    jwks_uri: HttpUrl
    userinfo_endpoint: HttpUrl | None = None


class TokenResponse(BaseModel):
    """Token response payload defined by RFC 6749."""

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None


@dataclass(slots=True)
class TokenSet:
    """Container keeping the current OAuth tokens."""

    access_token: str
    token_type: str
    expires_in: int | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    scope: tuple[str, ...] | None = None


class OIDCClient:
    """High level OIDC client capable of performing code flow with PKCE."""

    def __init__(
        self,
        issuer: str,
        client_id: str,
        redirect_uri: str,
        client_secret: str | None = None,
        scope: tuple[str, ...] = ("openid",),
        audience: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scope = scope
        self._audience = audience
        self._timeout = timeout
        self._metadata: OIDCProviderMetadata | None = None
        self._http = httpx.AsyncClient(timeout=timeout)

    async def _fetch_metadata(self) -> OIDCProviderMetadata:
        if self._metadata is None:
            url = f"{self._issuer}/.well-known/openid-configuration"
            response = await self._http.get(url)
            response.raise_for_status()
            self._metadata = OIDCProviderMetadata.model_validate(response.json())
        return self._metadata

    async def get_metadata(self) -> OIDCProviderMetadata:
        return await self._fetch_metadata()

    async def generate_pkce_pair(self) -> tuple[str, str]:
        verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
        return verifier, challenge

    async def build_authorization_url(self, state: str | None = None) -> tuple[str, str, str]:
        metadata = await self._fetch_metadata()
        code_verifier, code_challenge = await self.generate_pkce_pair()
        state = state or secrets.token_urlsafe(16)
        scope = " ".join(self._scope)
        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self._redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if self._audience:
            params["audience"] = self._audience
        url = httpx.URL(str(metadata.authorization_endpoint)).copy_add_params(params)
        return str(url), state, code_verifier

    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
        additional_params: Mapping[str, Any] | None = None,
    ) -> TokenSet:
        metadata = await self._fetch_metadata()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri,
            "client_id": self._client_id,
            "code_verifier": code_verifier,
        }
        if self._client_secret:
            data["client_secret"] = self._client_secret
        if additional_params:
            data.update(additional_params)
        response = await self._http.post(metadata.token_endpoint, data=data)
        response.raise_for_status()
        return self._token_from_response(response.json())

    async def refresh(self, refresh_token: str) -> TokenSet:
        metadata = await self._fetch_metadata()
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._client_id,
        }
        if self._client_secret:
            data["client_secret"] = self._client_secret
        response = await self._http.post(metadata.token_endpoint, data=data)
        response.raise_for_status()
        return self._token_from_response(response.json())

    def _token_from_response(self, payload: Mapping[str, Any]) -> TokenSet:
        token = TokenResponse.model_validate(payload)
        scope = tuple(token.scope.split()) if token.scope else None
        return TokenSet(
            access_token=token.access_token,
            token_type=token.token_type,
            expires_in=token.expires_in,
            refresh_token=token.refresh_token,
            id_token=token.id_token,
            scope=scope,
        )

    async def aclose(self) -> None:
        await self._http.aclose()


__all__ = ["OIDCClient", "OIDCProviderMetadata", "TokenSet"]
