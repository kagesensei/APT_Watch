import functools
import os

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, jsonify, redirect, session, url_for

bp = Blueprint("auth", __name__)

oauth = OAuth()

GOOGLE_CONFIGURED = bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))


def init_app(app):
    oauth.init_app(app)
    if GOOGLE_CONFIGURED:
        oauth.register(
            name="google",
            client_id=os.environ["GOOGLE_CLIENT_ID"],
            client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    @app.context_processor
    def inject_user():
        return {"current_user": current_user(), "google_login_available": GOOGLE_CONFIGURED}


def current_user():
    return session.get("user")


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return jsonify({"error": "Sign in required."}), 401
        return view(*args, **kwargs)

    return wrapped


@bp.route("/login/google")
def login_google():
    if not GOOGLE_CONFIGURED:
        return jsonify({"error": "Google sign-in is not configured on this server."}), 503
    redirect_uri = url_for("auth.auth_callback_google", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@bp.route("/auth/callback/google")
def auth_callback_google():
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
def logout():
    session.pop("user", None)
    return redirect(url_for("chat.index"))
