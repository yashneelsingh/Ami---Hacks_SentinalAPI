"""Authentication implementation for the controlled two-user demo."""

from __future__ import annotations

import json

from .interfaces import RequestExecutor
from .models import Credentials


class AuthenticationError(ValueError):
    """A controlled authentication failure safe to expose to the user."""


class PasswordAuthenticator:
    def authenticate(self, requester: RequestExecutor, credentials: Credentials, user_label: str) -> str:
        response = requester.request(
            "POST",
            "/auth/login",
            json={"email": credentials.email, "password": credentials.password},
        )
        if response.status_code != 200:
            raise AuthenticationError(f"Login failed for {user_label} (HTTP {response.status_code})")
        try:
            body = json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthenticationError(f"{user_label} login did not return JSON") from None
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            raise AuthenticationError(f"{user_label} login response has no access_token")
        return token

