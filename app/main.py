from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.database import database_session, ensure_database


TOKENS = {
    "demo-token-user-a": {"id": 1, "email": "user-a@example.test", "role": "customer"},
    "demo-token-user-b": {"id": 2, "email": "user-b@example.test", "role": "customer"},
}


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class OrderUpdate(BaseModel):
    shipping_address: str | None = Field(default=None, min_length=3, max_length=200)


def get_current_user(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")

    token = authorization.removeprefix("Bearer ")
    user = TOKENS.get(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid test token")
    return user


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_database()
    yield


app = FastAPI(
    title="SentinelAPI Vulnerable Demo",
    version="1.0.0",
    description="INTENTIONALLY VULNERABLE local-only API for authorized scanner demonstrations.",
    lifespan=lifespan,
)


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": "local-demo-only"}


@app.post("/auth/login", response_model=LoginResponse, tags=["authentication"])
def login(credentials: LoginRequest) -> LoginResponse:
    with database_session() as connection:
        user = connection.execute(
            "SELECT id, email, password FROM users WHERE email = ?", (credentials.email,)
        ).fetchone()

    if not user or credentials.password != user["password"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid test credentials")

    return LoginResponse(access_token=f"demo-token-user-{'a' if user['id'] == 1 else 'b'}")


@app.get("/orders", tags=["orders"])
def list_orders(current_user: Annotated[dict, Depends(get_current_user)]) -> list[dict]:
    with database_session() as connection:
        rows = connection.execute(
            "SELECT id, item_name, amount, shipping_address FROM orders WHERE owner_id = ? ORDER BY id",
            (current_user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.get("/orders/{order_id}", tags=["orders"])
def get_order(order_id: int, _: Annotated[dict, Depends(get_current_user)]) -> dict:
    """INTENTIONAL BOLA/IDOR FLAW: token presence is checked but ownership is not."""
    with database_session() as connection:
        row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")

    # Intentionally returns another user's order plus sensitive fields for the demo.
    return dict(row)


@app.patch("/orders/{order_id}", tags=["orders"])
def update_order(
    order_id: int,
    update: OrderUpdate,
    _: Annotated[dict, Depends(get_current_user)],
) -> dict:
    """INTENTIONAL BOLA/IDOR FLAW: an authenticated user can update any order."""
    if update.shipping_address is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="No supported fields provided")

    with database_session() as connection:
        existing = connection.execute("SELECT id FROM orders WHERE id = ?", (order_id,)).fetchone()
        if not existing:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
        connection.execute("UPDATE orders SET shipping_address = ? WHERE id = ?", (update.shipping_address, order_id))
        row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return dict(row)


@app.get("/profile", tags=["profile"])
def profile(current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """INTENTIONAL excessive-data-exposure example: role is returned to normal users."""
    return current_user
