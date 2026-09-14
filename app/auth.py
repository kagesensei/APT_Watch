"""Google OAuth sign-in and the session-backed current-user helpers."""

import functools
import os
from typing import Callable, ParamSpec, TypeVar

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, Flask, Response, jsonify, redirect, session, url_for
from werkzeug.wrappers import Response as WerkzeugResponse

bp = Blueprint("auth", __name__)

oauth = OAuth()

GOOGLE_CONFIGURED = bool(
    os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")
)

UserInfo = dict[str, object]

P = ParamSpec("P")
R = TypeVar("R")


def init_app(app: Flask) -> None:
    """Register Google OAuth (if configured) and the `current_user` template global."""
    oauth.init_app(app)
    if GOOGLE_CONFIGURED:
        oauth.register(  # type: ignore[no-untyped-call]  # authlib stub lacks a signature
            name="google",
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    @app.context_processor
    def inject_user() -> dict[str, object]:
        return {"current_user": current_user(), "google_login_available": GOOGLE_CONFIGURED}


def current_user() -> UserInfo | None:
    """Return the signed-in user's session record, or None if signed out."""
    return session.get("user")


def login_required(view: Callable[P, R]) -> Callable[P, R | tuple[Response, int]]:
    """Route decorator: reject with 401 JSON instead of calling the view."""

    @functools.wraps(view)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R | tuple[Response, int]:
        if current_user() is None:
            return jsonify({"error": "Sign in required."}), 401
        return view(*args, **kwargs)

    return wrapped


@bp.route("/login/google")
def login_google() -> Response | tuple[Response, int]:
    """Start the Google OAuth redirect flow."""
    if not GOOGLE_CONFIGURED:
        return jsonify({"error": "Google sign-in is not configured on this server."}), 503
    redirect_uri = url_for("auth.auth_callback_google", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)  # type: ignore[no-any-return]


@bp.route("/auth/callback/google")
def auth_callback_google() -> WerkzeugResponse | tuple[Response, int]:
    """Complete the Google OAuth flow and store the user in the session."""
    if not GOOGLE_CONFIGURED:
        return jsonify({"error": "Google sign-in is not configured on this server."}), 503
    token = oauth.google.authorize_access_token()
    userinfo = token.get("userinfo") or oauth.google.userinfo(token=token)
    session["user"] = {
        "id": userinfo["sub"],
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
        "picture": userinfo.get("picture"),
    }
    return redirect(url_for("chat.index"))


@bp.route("/logout")
def logout() -> WerkzeugResponse:
    """Clear the session and return to the chat home page."""
    session.pop("user", None)
    return redirect(url_for("chat.index"))
