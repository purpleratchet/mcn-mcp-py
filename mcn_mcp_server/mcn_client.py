"""API client for the MCN commerce endpoints."""

from __future__ import annotations

from typing import Any, Mapping

import httpx

from .oidc import OIDCClient, TokenSet


class McnApiClient:
    """Wrapper handling authenticated calls to the MCN Shop API."""

    def __init__(
        self,
        *,
        oidc_client: OIDCClient,
        api_base_url: str = "https://shop.mcn.ru/api",
    ) -> None:
        self._oidc = oidc_client
        self._api_base_url = api_base_url.rstrip("/")
        self._http = httpx.AsyncClient(timeout=15.0)
        self._tokens: TokenSet | None = None

    async def generate_login(self, state: str | None = None) -> tuple[str, str, str]:
        """Return authorization URL, state, and PKCE verifier."""

        return await self._oidc.build_authorization_url(state=state)

    async def complete_login(
        self,
        *,
        code: str,
        code_verifier: str,
        state: str | None = None,
        expected_state: str | None = None,
    ) -> TokenSet:
        """Exchange an authorization code for tokens and cache them."""

        if expected_state is not None and state != expected_state:
            raise ValueError("State parameter mismatch during OAuth exchange")
        tokens = await self._oidc.exchange_code(code, code_verifier)
        self._tokens = tokens
        return tokens

    @property
    def tokens(self) -> TokenSet | None:
        return self._tokens

    async def ensure_tokens(self) -> TokenSet:
        if self._tokens is None:
            raise RuntimeError("Authorization has not been completed yet")
        return self._tokens

    async def _auth_headers(self) -> Mapping[str, str]:
        tokens = await self.ensure_tokens()
        return {"Authorization": f"{tokens.token_type} {tokens.access_token}"}

    async def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        url = f"{self._api_base_url}/{path.lstrip('/')}"
        response = await self._http.get(url, params=params, headers=await self._auth_headers())
        response.raise_for_status()
        return response.json()

    async def aclose(self) -> None:
        await self._http.aclose()
        await self._oidc.aclose()


__all__ = ["McnApiClient"]
