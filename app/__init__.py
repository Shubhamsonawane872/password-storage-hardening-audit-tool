"""Password Storage Hardening Audit Tool - Flask Application Factory"""
from flask import Flask, request, jsonify, render_template, session
from app.config import Config
from app.db import init_db, close_db


def create_app(config_class=Config):
    """Application factory function"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize database
    init_db(app)

    # Register DB teardown
    app.teardown_appcontext(close_db)

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.auth.profile_routes import profile_bp
    from app.dashboard.routes import dashboard_bp
    from app.scanner.routes import scanner_bp
    from app.reports.routes import reports_bp
    from app.admin.routes import admin_bp
    from app.views import views_bp
    from app.api.advanced_routes import advanced_api

    app.register_blueprint(views_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(advanced_api)

    # ── Context processor — injects current_user into every template ──────
    @app.context_processor
    def inject_current_user():
        user = None
        if "user_id" in session:
            from app.db import get_db_connection
            db = get_db_connection(app.config["DATABASE_PATH"])
            row = db.execute(
                "SELECT id, name, email, role FROM users WHERE id=?",
                (session["user_id"],),
            ).fetchone()
            db.close()
            if row:
                user = dict(row)
        return {"current_user": user}

    # Start background scheduler (skip in testing to avoid thread noise)
    if not app.config.get("TESTING"):
        from app.scheduler import start_scheduler
        start_scheduler(app)

    # Register error handlers
    _register_error_handlers(app)

    return app


def _register_error_handlers(app):
    """Return HTML for browser requests, JSON for API/XHR requests."""

    def _wants_json():
        return (
            request.path.startswith("/api/")
            or request.accept_mimetypes.best == "application/json"
        )

    @app.errorhandler(400)
    def bad_request(e):
        if _wants_json():
            return jsonify({"error": "Bad Request", "message": str(e)}), 400
        return render_template("errors/400.html"), 400

    @app.errorhandler(401)
    def unauthorized(e):
        if _wants_json():
            return jsonify({"error": "Unauthorized", "message": "Authentication required."}), 401
        return render_template("errors/401.html"), 401

    @app.errorhandler(403)
    def forbidden(e):
        if _wants_json():
            return jsonify({"error": "Forbidden", "message": "Access denied."}), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        if _wants_json():
            return jsonify({"error": "Not Found", "message": "Resource not found."}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        if _wants_json():
            return jsonify({"error": "Server Error", "message": "An unexpected error occurred."}), 500
        return render_template("errors/500.html"), 500
