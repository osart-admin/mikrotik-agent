"""Session-cookie auth. The service holds SSH keys to the whole fleet, so nothing is public."""
from __future__ import annotations

import bcrypt
from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse

from . import db

PUBLIC_PATHS = {"/login", "/setup", "/health", "/static"}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def current_user(request: Request) -> dict | None:
    username = request.session.get("user")
    if not username:
        return None
    row = db.get_user(username)
    if row is None:
        request.session.clear()
        return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def require_user(request: Request) -> dict:
    user = current_user(request)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
    return user


def login_redirect(request: Request) -> RedirectResponse:
    nxt = request.url.path
    return RedirectResponse(f"/login?next={nxt}", status_code=status.HTTP_303_SEE_OTHER)
