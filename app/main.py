from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.database import database_session, ensure_database
from scanner.core import Credentials, scan
from scanner.openapi_parser import MAX_SPEC_BYTES
from scanner.report_generator import markdown_report, write_reports


TOKENS = {
    "demo-token-user-a": {"id": 1, "email": "user-a@example.test", "role": "customer"},
    "demo-token-user-b": {"id": 2, "email": "user-b@example.test", "role": "customer"},
}
bearer_scheme = HTTPBearer(auto_error=False)


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class OrderUpdate(BaseModel):
    shipping_address: str | None = Field(default=None, min_length=3, max_length=200)


class ScanRequest(BaseModel):
    spec: str | None = None


def get_current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer token required")

    token = credentials.credentials
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

ROOT = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(ROOT / "app" / "static" / "index.html")


@app.post("/api/scan", tags=["scanner"])
def run_demo_scan(request: Request, options: ScanRequest | None = None) -> dict:
    if options and options.spec and len(options.spec.encode("utf-8")) > MAX_SPEC_BYTES:
        raise HTTPException(status_code=413, detail=f"OpenAPI document exceeds the {MAX_SPEC_BYTES}-byte limit")
    spec = options.spec if options and options.spec else (ROOT / "openapi.yaml").read_text(encoding="utf-8")
    try:
        report = scan(
            spec=spec,
            base_url=str(request.base_url),
            user_a=Credentials("user-a@example.test", "demo-password-a"),
            user_b=Credentials("user-b@example.test", "demo-password-b"),
        )
    except (ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from None
    write_reports(report, ROOT / "reports")
    return {"report": report, "markdown": markdown_report(report)}


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
