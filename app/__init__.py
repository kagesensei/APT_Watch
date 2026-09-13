from flask import Flask, render_template
from werkzeug.exceptions import HTTPException

from . import cache as cache_module
from . import db as db_module


def create_app():
    app = Flask(__name__)

    db_module.init_app(app)
    cache_module.init_app(app)

    from .routes import bp

    app.register_blueprint(bp)

    from .chat import bp as chat_bp

    app.register_blueprint(chat_bp)

    register_error_handlers(app)

    return app


def register_error_handlers(app):
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html", error=e), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return render_template("errors/405.html", error=e), 405

    @app.errorhandler(500)
    def internal_error(e):
        return render_template("errors/500.html", error=e), 500

    @app.errorhandler(HTTPException)
    def http_exception(e):
        return render_template("errors/generic.html", error=e), e.code

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        app.logger.exception(e)
        return render_template("errors/500.html", error=e), 500
