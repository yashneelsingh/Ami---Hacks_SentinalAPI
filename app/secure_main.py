"""Secure local control target for demonstrating a negative SentinelAPI scan."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.database import database_session, ensure_database


TOKENS = {
    "secure-demo-token-user-a": {"id": 1, "email": "user-a@example.test"},
    "secure-demo-token-user-b": {"id": 2, "email": "user-b@example.test"},
}
bearer_scheme = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")
    user = TOKENS.get(credentials.credentials)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid test token")
    return user


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_database()
    yield


app = FastAPI(
    title="SentinelAPI Secure Control",
    version="1.0.0",
    description="Local-only secure comparison target for authorized SentinelAPI demonstrations.",
    lifespan=lifespan,
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": "local-secure-control"}


@app.post("/auth/login", response_model=LoginResponse, tags=["authentication"])
def login(credentials: LoginRequest) -> LoginResponse:
    with database_session() as connection:
        user = connection.execute(
            "SELECT id, email, password FROM users WHERE email = ?", (credentials.email,)
        ).fetchone()
    if not user or credentials.password != user["password"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid test credentials")
    suffix = "a" if user["id"] == 1 else "b"
    return LoginResponse(access_token=f"secure-demo-token-user-{suffix}")


@app.get("/orders", tags=["orders"])
def list_orders(current_user: Annotated[dict, Depends(get_current_user)]) -> list[dict]:
    with database_session() as connection:
        rows = connection.execute(
            "SELECT id, item_name, amount, shipping_address FROM orders WHERE owner_id = ? ORDER BY id",
            (current_user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/orders/{order_id}", tags=["orders"])
def get_order(order_id: int, current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    with database_session() as connection:
        row = connection.execute(
            """
            SELECT id, item_name, amount, shipping_address
            FROM orders
            WHERE id = ? AND owner_id = ?
            """,
            (order_id, current_user["id"]),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Order access denied")
    return dict(row)
