"""Flask application factory: wires up the DB, cache, auth, and each
blueprint, and registers a themed error page for every HTTP error status.
"""

import os
import secrets

from flask import Flask, Response, render_template
from werkzeug.exceptions import HTTPException

from . import auth as auth_module
from . import cache as cache_module
from . import db as db_module


def create_app() -> Flask:
    """Build and configure the Flask app. The entry point for both the dev
    server (main.py) and the test suite (tests/conftest.py's `app` fixture).
    """
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB, for the scan-page file upload

    app.secret_key = os.environ.get("APTWATCH_SECRET_KEY")
    if not app.secret_key:
        app.secret_key = secrets.token_hex(32)
        app.logger.warning(
            "APTWATCH_SECRET_KEY not set - using a random per-process key. "
            "Sessions (and Google sign-in) will not survive a restart. "
            "Set APTWATCH_SECRET_KEY for anything beyond local testing."
        )

    db_module.init_app(app)
    cache_module.init_app(app)
    auth_module.init_app(app)

    # Deferred imports, not just organization: app.chat pulls in app.llm,
    # which preloads native DLLs and can load an 8B-parameter GGUF model at
    # import time. Importing it eagerly here would mean `import app` alone
    # -- e.g. `from app import cache` in a test fixture that only wants the
    # DB layer -- pays that cost too. Keeping these local to create_app()
    # means only code that actually builds a full app instance pays it.
    from .routes import bp  # pylint: disable=import-outside-toplevel

    app.register_blueprint(bp)

    from .chat import bp as chat_bp  # pylint: disable=import-outside-toplevel

    app.register_blueprint(chat_bp)

    from .preview import bp as preview_bp  # pylint: disable=import-outside-toplevel

    app.register_blueprint(preview_bp)

    from .scan import bp as scan_bp  # pylint: disable=import-outside-toplevel

    app.register_blueprint(scan_bp)

    from .dashboard import bp as dashboard_bp  # pylint: disable=import-outside-toplevel

    app.register_blueprint(dashboard_bp)

    app.register_blueprint(auth_module.bp)

    register_error_handlers(app)

    return app


def register_error_handlers(app: Flask) -> None:
    """Render a themed error page for each HTTP error status this app expects."""

    @app.errorhandler(400)
    def bad_request(e: HTTPException) -> tuple[str, int]:
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(403)
    def forbidden(e: HTTPException) -> tuple[str, int]:
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e: HTTPException) -> tuple[str, int]:
        return render_template("errors/404.html", error=e), 404

    @app.errorhandler(405)
    def method_not_allowed(e: HTTPException) -> tuple[str, int]:
        return render_template("errors/405.html", error=e), 405

    @app.errorhandler(500)
    def internal_error(e: HTTPException) -> tuple[str, int]:
        return render_template("errors/500.html", error=e), 500

    @app.errorhandler(HTTPException)
    def http_exception(e: HTTPException) -> tuple[str, int]:
        return render_template("errors/generic.html", error=e), e.code or 500

    @app.errorhandler(Exception)
    def unhandled_exception(e: Exception) -> tuple[Response | str, int]:
        app.logger.exception(e)
        return render_template("errors/500.html", error=e), 500
