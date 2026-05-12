"""
CyberAI Flask API server.
REST interface for starting scans, querying sessions, serving reports.
"""
from flask import Flask, jsonify
from cyberai.web.routes.session import session_bp
from cyberai.web.routes.report import report_bp
import logging

logger = logging.getLogger("cyberai.web")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    # Register blueprints
    app.register_blueprint(session_bp, url_prefix="/api")
    app.register_blueprint(report_bp,  url_prefix="/api")

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "CyberAI API"})

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "internal server error"}), 500

    logger.info("CyberAI API server created")
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8888, debug=False)
