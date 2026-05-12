"""
/api/report — serve generated markdown/JSON reports.
"""
from flask import Blueprint, jsonify, send_file, abort
from pathlib import Path
import os

report_bp = Blueprint("report", __name__)

REPORTS_DIR = Path(os.getenv("CYBERAI_REPORTS_DIR", "reports/"))


@report_bp.get("/report")
def list_reports():
    """GET /api/report — list available report files."""
    if not REPORTS_DIR.exists():
        return jsonify({"reports": [], "count": 0})

    files = [
        {
            "filename": f.name,
            "size_bytes": f.stat().st_size,
            "modified": f.stat().st_mtime,
        }
        for f in REPORTS_DIR.iterdir()
        if f.suffix in (".md", ".json", ".html", ".pdf")
    ]
    files.sort(key=lambda x: x["modified"], reverse=True)
    return jsonify({"reports": files, "count": len(files)})


@report_bp.get("/report/<filename>")
def get_report(filename: str):
    """
    GET /api/report/<filename>
    Serves the report file. Sanitizes path to prevent traversal.
    """
    # Path traversal guard
    safe_name = Path(filename).name
    report_path = REPORTS_DIR / safe_name

    if not report_path.exists():
        abort(404)

    suffix = report_path.suffix.lower()
    mime_map = {
        ".md":   "text/markdown",
        ".json": "application/json",
        ".html": "text/html",
        ".pdf":  "application/pdf",
    }
    mimetype = mime_map.get(suffix, "application/octet-stream")
    return send_file(report_path, mimetype=mimetype)
