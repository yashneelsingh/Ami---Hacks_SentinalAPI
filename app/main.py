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

from app.database import DEMO_SEED_VERSION, database_session, ensure_database
from scanner.core import Credentials, ScanError, scan
from scanner.openapi_parser import MAX_SPEC_BYTES
from scanner.report_generator import markdown_report, write_reports
from scanner.structured_logging import configure_logging, log_event


TOKENS = {
    "demo-token-user-a": {"id": 1, "email": "user-a@example.test", "role": "customer"},
    "demo-token-user-b": {"id": 2, "email": "user-b@example.test", "role": "customer"},
}
bearer_scheme = HTTPBearer(auto_error=False)
logger = configure_logging()


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScanRequest(BaseModel):
    spec: str | None = None
    base_url: str | None = Field(default=None, min_length=1, max_length=2048)


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
    return FileResponse(
        ROOT / "app" / "static" / "index.html",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/scan", tags=["scanner"])
def run_demo_scan(request: Request, options: ScanRequest | None = None) -> dict:
    if options and options.spec and len(options.spec.encode("utf-8")) > MAX_SPEC_BYTES:
        raise HTTPException(status_code=413, detail=f"OpenAPI document exceeds the {MAX_SPEC_BYTES}-byte limit")
    spec = options.spec if options and options.spec else (ROOT / "openapi.yaml").read_text(encoding="utf-8")
    try:
        report = scan(
            spec=spec,
            base_url=options.base_url.strip() if options and options.base_url else str(request.base_url),
            user_a=Credentials("user-a@example.test", "demo-password-a"),
            user_b=Credentials("user-b@example.test", "demo-password-b"),
        )
    except ScanError as exc:
        log_event(logger, "scan_request_rejected", level=30, error_type=type(exc).__name__)
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except ValueError as exc:
        log_event(logger, "scan_request_rejected", level=30, error_type=type(exc).__name__)
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except httpx.HTTPError as exc:
        log_event(logger, "scan_request_failed", level=40, error_type=type(exc).__name__)
        raise HTTPException(status_code=502, detail="Local target request failed") from None
    report["fixture_version"] = DEMO_SEED_VERSION
    try:
        write_reports(report, ROOT / "reports")
    except OSError:
        log_event(logger, "scan_report_write_failed", level=40)
        raise HTTPException(status_code=500, detail="Could not save scan reports") from None
    log_event(logger, "scan_report_written", formats=["json", "markdown"])
    return {"report": report, "markdown": markdown_report(report)}


def _report_download(filename: str, media_type: str) -> FileResponse:
    report_path = ROOT / "reports" / filename
    if not report_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run a scan before downloading reports")
    return FileResponse(
        report_path,
        media_type=media_type,
        filename=filename,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/api/reports/sentinel_report.json", include_in_schema=False)
def download_json_report() -> FileResponse:
    return _report_download("sentinel_report.json", "application/json")


@app.get("/api/reports/sentinel_report.md", include_in_schema=False)
def download_markdown_report() -> FileResponse:
    return _report_download("sentinel_report.md", "text/markdown; charset=utf-8")


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


@app.get("/secure-orders", tags=["jury-demo-controls"])
def list_secure_orders(current_user: Annotated[dict, Depends(get_current_user)]) -> list[dict]:
    """Expose the same owner-filtered collection for the secure jury control."""
    return list_orders(current_user)


@app.get("/secure-orders/{order_id}", tags=["jury-demo-controls"])
def get_secure_order(order_id: int, current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """Return an allowlisted order view only to its owner."""
    order = _owned_order(order_id, current_user)
    return {key: order[key] for key in ("id", "item_name", "amount", "shipping_address")}


@app.get("/unstable-orders", tags=["jury-demo-controls"])
def list_unstable_orders(current_user: Annotated[dict, Depends(get_current_user)]) -> list[dict]:
    """Expose owner-filtered objects for the inconclusive jury control."""
    return list_orders(current_user)


@app.get("/unstable-orders/{order_id}", tags=["jury-demo-controls"])
def get_unstable_order(order_id: int, current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """Simulate an ambiguous rate-limited cross-user response without claiming BOLA."""
    with database_session() as connection:
        row = connection.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    if row["owner_id"] != current_user["id"]:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Demo control is temporarily unavailable")
    order = dict(row)
    return {key: order[key] for key in ("id", "item_name", "amount", "shipping_address")}


def _owned_order(order_id: int, current_user: dict) -> dict:
    """Load an order only when it belongs to the authenticated local demo user."""
    with database_session() as connection:
        row = connection.execute(
            "SELECT * FROM orders WHERE id = ? AND owner_id = ?",
            (order_id, current_user["id"]),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Order access is not permitted")
    return dict(row)


@app.get("/orders/{order_id}/summary", tags=["orders"])
def order_summary(order_id: int, current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """A safe, owner-scoped summary endpoint for the local demo."""
    order = _owned_order(order_id, current_user)
    return {key: order[key] for key in ("id", "item_name", "amount", "shipping_address")}


@app.get("/orders/{order_id}/tracking", tags=["orders"])
def order_tracking(order_id: int, current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """A safe, owner-scoped shipping-status endpoint for the local demo."""
    _owned_order(order_id, current_user)
    return {"order_id": order_id, "carrier": "LocalPost", "status": "label_created"}


@app.get("/orders/{order_id}/receipt", tags=["orders"])
def order_receipt(order_id: int, current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """A safe receipt view that returns only a masked payment reference."""
    order = _owned_order(order_id, current_user)
    return {
        "order_id": order_id,
        "amount": order["amount"],
        "payment_reference_last4": order["payment_reference"][-4:],
    }


@app.get("/orders/{order_id}/items", tags=["orders"])
def order_items(order_id: int, current_user: Annotated[dict, Depends(get_current_user)]) -> list[dict]:
    """A safe, owner-scoped line-item endpoint for the local demo."""
    order = _owned_order(order_id, current_user)
    return [{"sku": f"demo-{order_id}", "name": order["item_name"], "quantity": 1, "unit_amount": order["amount"]}]


@app.get("/profile", tags=["profile"])
def profile(current_user: Annotated[dict, Depends(get_current_user)]) -> dict:
    """INTENTIONAL excessive-data-exposure example: role is returned to normal users."""
    return current_user
