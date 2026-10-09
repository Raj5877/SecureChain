from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash

from . import crypto
from .service import EvidenceService, Problem, now, validate_history


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATA_DIR=os.getenv("SECURECHAIN_DATA_DIR", "instance"),
        NODE_NAME=os.getenv("SECURECHAIN_NODE_NAME", "Investigation Lab"),
        MASTER_KEY=os.getenv("SECURECHAIN_MASTER_KEY"),
        ALLOW_LOOPBACK_HTTP=os.getenv("SECURECHAIN_ALLOW_LOOPBACK_HTTP", "0") == "1",
        RECEIVE_TOKEN=os.getenv("SECURECHAIN_RECEIVE_TOKEN", ""),
        MAX_FILE_SIZE=32 * 1024 * 1024,
        MAX_CONTENT_LENGTH=80 * 1024 * 1024,
        MAX_FORM_MEMORY_SIZE=128 * 1024,
        MAX_FORM_PARTS=30,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.getenv("SECURECHAIN_SECURE_COOKIES", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        SESSION_REFRESH_EACH_REQUEST=False,
    )
    if config:
        app.config.update(config)
    service = EvidenceService(Path(app.config["DATA_DIR"]).resolve(), app.config["NODE_NAME"], app.config["MASTER_KEY"], app.config["MAX_FILE_SIZE"], app.config["ALLOW_LOOPBACK_HTTP"])
    app.extensions["securechain"] = service
    app.config["SECRET_KEY"] = hmac.new(service.keys.master, b"securechain-session-v1", hashlib.sha256).digest()
    # Two local demonstration nodes must not overwrite one another's cookies.
    app.config["SESSION_COOKIE_NAME"] = "securechain_" + service.keys.node_id[-16:].lower()

    def current_user():
        user_id = session.get("user_id")
        return service.db.one("SELECT * FROM users WHERE id=?", (user_id,)) if user_id else None

    def public_user(user):
        return {key: user[key] for key in ("id", "username", "name", "role")}

    def authenticated(*roles):
        def decorate(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                user = current_user()
                if not user:
                    raise Problem("Sign in to continue.", 401)
                if roles and user["role"] not in roles:
                    raise Problem("Your role does not allow this action.", 403)
                return fn(user, *args, **kwargs)
            return wrapped
        return decorate

    def json_body():
        data = request.get_json()
        if not isinstance(data, dict):
            raise Problem("Expected a JSON object.")
        return data

    def text_field(data, field, default=""):
        value = data.get(field, default)
        if not isinstance(value, str):
            raise Problem(f"{field} must be text.")
        return value

    @app.before_request
    def csrf_guard():
        # Reject oversized evidence requests before parsing multipart content.
        if request.method == "POST" and (request.path == "/api/evidence" or
                (request.path.startswith("/api/evidence/") and request.path.endswith("/verify"))):
            request.max_content_length = service.max_file_size + 256 * 1024
        elif request.path in {"/api/packages/import", "/api/node/receive"}:
            request.max_content_length = service.max_package_size + 256 * 1024
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path != "/api/node/receive":
            expected = session.get("csrf")
            submitted = request.headers.get("X-CSRF-Token", "")
            if not expected or not secrets.compare_digest(expected, submitted):
                raise Problem("Your session expired. Refresh this page and try again.", 403)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.errorhandler(Problem)
    def problem(exc):
        body = {"error": str(exc)}
        if exc.analysis and request.path != "/api/node/receive" and current_user():
            body.update(analysis=exc.analysis, evidence_id=exc.analysis.get("evidence_id"))
        elif exc.analysis and request.path == "/api/node/receive":
            body["error"] = "Transfer package rejected. Check the receiving node audit log."
        return jsonify(body), exc.status

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error="Upload exceeds the request limit." if exc.code == 413 else exc.description), exc.code

    @app.errorhandler(Exception)
    def unexpected_error(exc):
        if app.testing:
            raise exc
        app.logger.exception("SecureChain operation failed")
        return jsonify(error="The operation could not be completed. Check the server log."), 500

    @app.get("/")
    def index():
        session.setdefault("csrf", secrets.token_urlsafe(32))
        return render_template("index.html", node_name=service.name, csrf=session["csrf"])

    @app.get("/api/session")
    def session_info():
        session.setdefault("csrf", secrets.token_urlsafe(32))
        user = current_user()
        return jsonify(user=public_user(user) if user else None, csrf=session["csrf"],
                       setup_required=not service.db.one("SELECT id FROM users LIMIT 1"), node_name=service.name)

    @app.post("/api/setup")
    def setup():
        data = json_body()
        user_id = service.create_user(text_field(data, "username"), text_field(data, "name"), text_field(data, "password"), "admin", initial=True)
        session.clear()
        session.update(user_id=user_id, csrf=secrets.token_urlsafe(32))
        session.permanent = True
        return jsonify(user=public_user(current_user()), csrf=session["csrf"]), 201

    @app.post("/api/login")
    def login():
        data = json_body()
        username = text_field(data, "username").strip().lower()[:64]
        password = text_field(data, "password")
        if len(password) > 256:
            raise Problem("Invalid username or password.", 401)
        attempt_key = crypto.digest((request.remote_addr + ":" + username).encode())
        current_time = time.time()
        with service.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM login_attempts WHERE key=?", (attempt_key,)).fetchone()
            if previous and previous["failures"] >= 8 and current_time - previous["last_attempt"] < 600:
                raise Problem("Too many sign-in attempts. Try again in 10 minutes.", 429)
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            valid = bool(user and check_password_hash(user["password_hash"], password))
            if not valid:
                failures = previous["failures"] + 1 if previous and current_time - previous["last_attempt"] < 600 else 1
                db.execute("INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)", (attempt_key, failures, current_time))
                service._append(db, None, username or "unknown", "login_failed", {"address": request.remote_addr})
            else:
                db.execute("DELETE FROM login_attempts WHERE key=?", (attempt_key,))
                service._append(db, None, username, "login", {})
        if not valid:
            raise Problem("Invalid username or password.", 401)
        session.clear()
        session.update(user_id=user["id"], csrf=secrets.token_urlsafe(32))
        session.permanent = True
        return jsonify(user=public_user(dict(user)), csrf=session["csrf"])

    @app.post("/api/logout")
    @authenticated()
    def logout(user):
        service.log(None, user["username"], "logout")
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/dashboard")
    @authenticated()
    def dashboard(user):
        service.log(None, user["username"], "dashboard_accessed")
        return jsonify(service.summary())

    @app.get("/api/updates")
    @authenticated()
    def updates(user):
        # Background refreshes must not add audit events of their own.
        return jsonify(service.summary())

    @app.post("/api/evidence")
    @authenticated("admin", "investigator")
    def register(user):
        file = request.files.get("file")
        if not file or not file.filename:
            raise Problem("Choose an evidence file.")
        data = file.read(service.max_file_size + 1)
        evidence_id = service.register(data, file.filename, request.form.to_dict(), user)
        return jsonify(evidence_id=evidence_id), 201

    @app.get("/api/evidence/<evidence_id>")
    @authenticated()
    def evidence_detail(user, evidence_id):
        record = service.record(evidence_id)
        service.log(evidence_id, user["username"], "accessed")
        return jsonify(id=evidence_id, manifest=record["manifest"], status=record["status"], last_verified=record["last_verified"],
                       archived=record["archived"], archived_at=record["archived_at"], archived_by=record["archived_by"],
                       signature=record["signature"], signer_key=record["signer_key"], custody=service.history(record),
                       custody_valid=validate_history(service.history(record), evidence_id))

    @app.post("/api/evidence/<evidence_id>/verify")
    @authenticated("admin", "investigator")
    def verify(user, evidence_id):
        file = request.files.get("file")
        candidate = file.read(service.max_file_size + 1) if file else None
        if candidate is not None and len(candidate) > service.max_file_size:
            raise Problem("Candidate exceeds the file size limit.", 413)
        return jsonify(service.verify_evidence(evidence_id, user["username"], candidate,
                                              candidate_name=file.filename if file else None))

    @app.post("/api/evidence/<evidence_id>/archive")
    @authenticated("admin", "investigator")
    def archive(user, evidence_id):
        return jsonify(service.archive_evidence(evidence_id, user["username"]))

    @app.post("/api/evidence/<evidence_id>/restore")
    @authenticated("admin", "investigator")
    def restore(user, evidence_id):
        return jsonify(service.restore_evidence(evidence_id, user["username"]))

    @app.get("/api/evidence/<evidence_id>/download")
    @authenticated()
    def download(user, evidence_id):
        data, filename = service.download(evidence_id, user["username"])
        return send_file(io.BytesIO(data), mimetype="application/octet-stream", as_attachment=True, download_name=filename)

    @app.get("/api/evidence/<evidence_id>/report")
    @authenticated()
    def report(user, evidence_id):
        data = service.report(evidence_id, user["username"])
        return send_file(io.BytesIO(json.dumps(data, indent=2).encode()), mimetype="application/json", as_attachment=True, download_name=f"{evidence_id}-report.json")

    @app.get("/api/node/identity")
    def identity():
        return jsonify(service.keys.descriptor(service.name))

    @app.get("/api/node/identity/download")
    @authenticated()
    def identity_download(user):
        return send_file(io.BytesIO(json.dumps(service.keys.descriptor(service.name), indent=2).encode()), mimetype="application/json", as_attachment=True, download_name=f"{service.keys.node_id}-identity.json")

    @app.post("/api/peers")
    @authenticated("admin")
    def add_peer(user):
        data = json_body()
        node_id = service.add_peer(data.get("descriptor"), text_field(data, "url"), text_field(data, "token"), user["username"])
        return jsonify(node_id=node_id), 201

    @app.put("/api/peers/<node_id>")
    @authenticated("admin")
    def update_peer(user, node_id):
        data = json_body()
        return jsonify(service.update_peer(node_id, text_field(data, "url"),
                                           text_field(data, "token") if "token" in data else None,
                                           user["username"]))

    @app.post("/api/evidence/<evidence_id>/export")
    @authenticated("admin", "investigator")
    def export(user, evidence_id):
        package, package_id = service.export_package(evidence_id, text_field(json_body(), "peer_id"), user["username"])
        return send_file(io.BytesIO(package), mimetype="application/octet-stream", as_attachment=True, download_name=f"{evidence_id}-{package_id[:8]}.scpkg")

    @app.post("/api/evidence/<evidence_id>/transfer")
    @authenticated("admin", "investigator")
    def transfer(user, evidence_id):
        return jsonify(service.send_package(evidence_id, text_field(json_body(), "peer_id"), user["username"]))

    @app.post("/api/packages/import")
    @authenticated("admin", "investigator")
    def import_package(user):
        file = request.files.get("file")
        if not file:
            raise Problem("Choose a SecureChain package.")
        receipt = service.receive_package(file.read(service.max_package_size + 1), user["username"])
        return jsonify(receipt), 201

    @app.post("/api/node/receive")
    def receive():
        if not service.db.one("SELECT id FROM users LIMIT 1"):
            raise Problem("Configure the receiving node first.", 403)
        expected = app.config["RECEIVE_TOKEN"]
        if expected and not secrets.compare_digest(request.headers.get("Authorization", ""), "Bearer " + expected):
            raise Problem("Invalid node receive token.", 403)
        if request.mimetype != "application/json":
            raise Problem("Transfer content type must be application/json.", 415)
        return jsonify(service.receive_package(request.get_data(), "node-transfer-service")), 201

    @app.post("/api/alerts/<int:alert_id>/acknowledge")
    @authenticated("admin", "investigator")
    def acknowledge(user, alert_id):
        alert = service.db.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if not alert:
            raise Problem("Alert not found.", 404)
        with service.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
            service._append(db, alert["evidence_id"], user["username"], "alert_acknowledged", {"alert_id": alert_id})
        return jsonify(ok=True)

    @app.get("/api/users")
    @authenticated("admin")
    def users(user):
        return jsonify(service.db.rows("SELECT id,username,name,role,created_at FROM users ORDER BY id"))

    @app.post("/api/users")
    @authenticated("admin")
    def new_user(user):
        data = json_body()
        user_id = service.create_user(text_field(data, "username"), text_field(data, "name"), text_field(data, "password"), text_field(data, "role", "investigator"), actor=user["username"])
        return jsonify(id=user_id), 201

    @app.get("/api/audit/export")
    @authenticated()
    def audit(user):
        service.log(None, user["username"], "audit_exported")
        events = service.events(all_events=True)
        body = {"format": "securechain-audit", "version": 1, "generated_at": now(), "node": service.keys.descriptor(service.name), "events": events, "valid": validate_history(events)}
        signed = {**body, "signature": crypto.sign(service.keys.signing, crypto.canonical(body))}
        return send_file(io.BytesIO(json.dumps(signed, indent=2).encode()), mimetype="application/json", as_attachment=True, download_name="securechain-audit.json")

    @app.get("/api/metrics/export")
    @authenticated()
    def metrics(user):
        service.log(None, user["username"], "metrics_exported")
        rows = service.db.rows("SELECT evidence_id,operation,hash_ms,signature_ms,encryption_ms,decryption_ms,total_ms,size_bytes,created_at FROM metrics ORDER BY id")
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=["evidence_id", "operation", "hash_ms", "signature_ms", "encryption_ms", "decryption_ms", "total_ms", "size_bytes", "created_at"])
        writer.writeheader()
        writer.writerows(rows)
        return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="securechain-metrics.csv")

    return app
