"""Evidence lifecycle, signed custody history and recipient-bound transfers."""
from __future__ import annotations

import json
import mimetypes
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from . import crypto
from .db import Database


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def milliseconds(start):
    return round((time.perf_counter() - start) * 1000, 3)


class Problem(ValueError):
    def __init__(self, message, status=400, analysis=None):
        super().__init__(message)
        self.status = status
        self.analysis = analysis


def validate_history(history, evidence_id=None):
    """Each node signs an independent, contiguous chain for each evidence scope."""
    if not isinstance(history, list):
        return False
    heads = {}
    for event in history:
        try:
            payload = event["payload"]
            if evidence_id and payload["scope"] != evidence_id:
                return False
            key = (payload["node_id"], payload["scope"])
            previous, sequence = heads.get(key, ("0" * 64, 0))
            if payload["node_id"] != "NODE-" + crypto.fingerprint(event["public_key"])[:16].upper():
                return False
            if payload["sequence"] != sequence + 1 or event["previous_hash"] != previous:
                return False
            expected = crypto.digest(crypto.canonical({"payload": payload, "previous_hash": previous}))
            if expected != event["event_hash"] or not crypto.verify(event["public_key"], expected.encode(), event["signature"]):
                return False
            heads[key] = (expected, payload["sequence"])
        except (KeyError, TypeError, ValueError, UnicodeError, AttributeError):
            return False
    return True


class EvidenceService:
    def __init__(self, directory: Path, name: str, master_key=None, max_file_size=32 * 1024 * 1024, allow_loopback=False):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        self.vault = directory / "vault"
        self.vault.mkdir(exist_ok=True)
        self.keys = crypto.Keyring(directory / "keys", master_key)
        self.db = Database(directory / "securechain.sqlite3")
        self.name = name
        self.max_file_size = max_file_size
        # Nested base64 adds about 78% to the original evidence size.
        self.max_package_size = 2 * max_file_size + 8 * 1024 * 1024
        self.allow_loopback = allow_loopback

    def create_user(self, username, name, password, role="investigator", actor=None, initial=False):
        username = username.strip().lower()
        if not username or len(username) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for c in username):
            raise Problem("Username must contain 1–64 letters, numbers, dots, hyphens or underscores.")
        if not name.strip() or len(name) > 120:
            raise Problem("Enter a name of up to 120 characters.")
        if not 12 <= len(password) <= 256:
            raise Problem("Use a password of 12–256 characters.")
        missing = []
        if not any("A" <= char <= "Z" for char in password):
            missing.append("an uppercase letter")
        if not any("a" <= char <= "z" for char in password):
            missing.append("a lowercase letter")
        if not any("0" <= char <= "9" for char in password):
            missing.append("a number")
        if not any(not char.isalnum() and not char.isspace() for char in password):
            missing.append("a special character")
        if missing:
            raise Problem("Password must include " + ", ".join(missing) + ".")
        if role not in {"admin", "investigator", "viewer"}:
            raise Problem("Invalid role.")
        key = crypto.new_key()
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if initial and db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                raise Problem("This node is already configured.", 409)
            if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                raise Problem("This username already exists.", 409)
            cursor = db.execute("INSERT INTO users(username,name,password_hash,role,public_key,private_key,created_at) VALUES(?,?,?,?,?,?,?)",
                (username, name.strip(), generate_password_hash(password, method="scrypt"), role, crypto.public_pem(key), self.keys.protect_handler(key, username), now()))
            self._append(db, None, actor or username, "user_created", {"username": username, "role": role})
            return cursor.lastrowid

    def _append(self, db, evidence_id, actor, action, detail):
        previous = db.execute("SELECT payload,event_hash FROM events WHERE evidence_id IS ? ORDER BY id DESC LIMIT 1", (evidence_id,)).fetchone()
        payload = {"scope": evidence_id or "system", "node_id": self.keys.node_id,
                   "sequence": json.loads(previous["payload"])["sequence"] + 1 if previous else 1,
                   "actor": actor, "action": action, "timestamp": now(), "detail": detail}
        previous_hash = previous["event_hash"] if previous else "0" * 64
        event_hash = crypto.digest(crypto.canonical({"payload": payload, "previous_hash": previous_hash}))
        db.execute("INSERT INTO events(evidence_id,payload,previous_hash,event_hash,signature,public_key) VALUES(?,?,?,?,?,?)",
            (evidence_id, crypto.canonical(payload).decode(), previous_hash, event_hash, crypto.sign(self.keys.signing, event_hash.encode()), crypto.public_pem(self.keys.signing)))

    def log(self, evidence_id, actor, action, detail=None):
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._append(db, evidence_id, actor, action, detail or {})

    def alert(self, evidence_id, message):
        with self.db.connect() as db:
            db.execute("INSERT INTO alerts(evidence_id,message,created_at) VALUES(?,?,?)", (evidence_id, message, now()))

    def events(self, evidence_id=None, all_events=False):
        rows = self.db.rows("SELECT * FROM events ORDER BY id" if all_events else "SELECT * FROM events WHERE evidence_id IS ? ORDER BY id", () if all_events else (evidence_id,))
        for row in rows:
            row["payload"] = json.loads(row["payload"])
        return rows

    def record(self, evidence_id):
        row = self.db.one("SELECT e.*, a.archived_at, a.archived_by FROM evidence e LEFT JOIN evidence_archive a ON a.evidence_id=e.id WHERE e.id=?", (evidence_id,))
        if not row:
            raise Problem("Evidence not found.", 404)
        row["manifest"] = json.loads(row["manifest"])
        row["imported_history"] = json.loads(row["imported_history"])
        row["archived"] = bool(row["archived_at"])
        return row

    def history(self, record):
        return record["imported_history"] + self.events(record["id"])

    def list_evidence(self, archived=False):
        rows = self.db.rows(
            "SELECT e.id,e.manifest,e.status,e.last_verified,e.registered_at,a.archived_at,a.archived_by "
            "FROM evidence e LEFT JOIN evidence_archive a ON a.evidence_id=e.id "
            "WHERE a.evidence_id IS " + ("NOT NULL" if archived else "NULL") + " ORDER BY e.registered_at DESC,e.id"
        )
        return [{**row, "manifest": json.loads(row["manifest"]), "archived": bool(row["archived_at"])} for row in rows]

    def archive_evidence(self, evidence_id, actor):
        self.record(evidence_id)
        archived_at = now()
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT evidence_id FROM evidence_archive WHERE evidence_id=?", (evidence_id,)).fetchone():
                raise Problem("This evidence record is already archived.", 409)
            db.execute("INSERT INTO evidence_archive VALUES(?,?,?)", (evidence_id, archived_at, actor))
            self._append(db, evidence_id, actor, "evidence_archived", {"archived_at": archived_at, "original_retained": True})
        return {"evidence_id": evidence_id, "archived": True, "archived_at": archived_at}

    def restore_evidence(self, evidence_id, actor):
        self.record(evidence_id)
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT evidence_id FROM evidence_archive WHERE evidence_id=?", (evidence_id,)).fetchone():
                raise Problem("This evidence record is already active.", 409)
            db.execute("DELETE FROM evidence_archive WHERE evidence_id=?", (evidence_id,))
            self._append(db, evidence_id, actor, "evidence_restored", {"original_retained": True})
        return {"evidence_id": evidence_id, "archived": False}

    def register(self, data: bytes, filename, metadata, user):
        total_start = time.perf_counter()
        if len(data) > self.max_file_size:
            raise Problem("Evidence exceeds the 32 MB file limit.", 413)
        filename = secure_filename(filename)[:180] or "evidence.bin"
        for field in ("case_id", "source", "description", "usb_serial"):
            if len(metadata.get(field, "")) > (2000 if field == "description" else 200):
                raise Problem(f"{field} is too long.")
        if not metadata.get("case_id", "").strip() or not metadata.get("source", "").strip():
            raise Problem("Case reference and acquisition source are required.")
        source_kind = metadata.get("source_kind", "manual")
        if source_kind not in {"manual", "usb", "network", "mobile"}:
            raise Problem("Invalid acquisition type.")
        acquired_at = metadata.get("acquired_at") or now()
        try:
            parsed = datetime.fromisoformat(acquired_at.replace("Z", "+00:00"))
            if not parsed.tzinfo:
                raise ValueError()
            acquired_at = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        except (ValueError, AttributeError):
            raise Problem("Acquisition time must be an ISO 8601 timestamp with a time zone.")
        evidence_id = "SC-" + uuid.uuid4().hex[:16].upper()
        start = time.perf_counter()
        file_hash = crypto.digest(data)
        hash_ms = milliseconds(start)
        manifest = {"version": 1, "evidence_id": evidence_id, "filename": filename,
                    "size_bytes": len(data), "sha256": file_hash, "mime_type": mimetypes.guess_type(filename)[0] or "application/octet-stream",
                    "case_id": metadata["case_id"].strip(), "source": metadata["source"].strip(), "source_kind": source_kind,
                    "usb_serial": metadata.get("usb_serial", "").strip(), "description": metadata.get("description", "").strip(),
                    "acquired_at": acquired_at, "registered_at": now(), "handler": user["username"], "handler_name": user["name"],
                    "origin_node": self.keys.node_id, "signer_fingerprint": crypto.fingerprint(user["public_key"])}
        start = time.perf_counter()
        signature = crypto.sign(self.keys.handler_key(user["private_key"], user["username"]), crypto.canonical(manifest))
        signature_ms = milliseconds(start)
        blob_name = uuid.uuid4().hex + ".enc"
        path = self.vault / blob_name
        start = time.perf_counter()
        encrypted = crypto.encrypt(self.keys.master, data, evidence_id.encode())
        encryption_ms = milliseconds(start)
        crypto.write_secret(path, encrypted)
        try:
            with self.db.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO evidence(id,manifest,signature,signer_key,blob_name,status,last_verified,registered_at) VALUES(?,?,?,?,?,?,?,?)",
                    (evidence_id, crypto.canonical(manifest).decode(), signature, user["public_key"], blob_name, "verified", now(), now()))
                self._append(db, evidence_id, user["username"], "registered", {"sha256": file_hash, "source": manifest["source"], "source_kind": source_kind})
                self._metric(db, evidence_id, "registration", hash_ms, signature_ms, milliseconds(total_start), len(data), encryption_ms=encryption_ms)
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return evidence_id

    def _metric(self, db, evidence_id, operation, hash_ms, signature_ms, total_ms, size, encryption_ms=None, decryption_ms=None):
        db.execute("INSERT INTO metrics(evidence_id,operation,hash_ms,signature_ms,total_ms,size_bytes,created_at,encryption_ms,decryption_ms) VALUES(?,?,?,?,?,?,?,?,?)",
            (evidence_id, operation, hash_ms, signature_ms, total_ms, size, now(), encryption_ms, decryption_ms))

    def _read(self, record):
        return self._read_timed(record)[0]

    def _read_timed(self, record):
        encrypted = (self.vault / record["blob_name"]).read_bytes()
        start = time.perf_counter()
        data = crypto.decrypt(self.keys.master, encrypted, record["id"].encode())
        return data, milliseconds(start)

    def verify_evidence(self, evidence_id, actor, candidate=None, candidate_name=None):
        total_start = time.perf_counter()
        record = self.record(evidence_id)
        manifest = record["manifest"]
        storage_ok = True
        error = None
        decryption_ms = None
        try:
            if candidate is None:
                data, decryption_ms = self._read_timed(record)
            else:
                data = candidate
        except (InvalidTag, OSError, ValueError):
            data = b""
            storage_ok = False
            error = "Encrypted vault file is missing, corrupted or cannot be authenticated."
        start = time.perf_counter()
        computed = crypto.digest(data) if storage_ok else None
        hash_ms = milliseconds(start)
        hash_ok = storage_ok and secrets.compare_digest(computed, manifest["sha256"]) and len(data) == manifest["size_bytes"]
        start = time.perf_counter()
        try:
            signature_ok = (manifest["evidence_id"] == evidence_id and
                crypto.fingerprint(record["signer_key"]) == manifest["signer_fingerprint"] and
                crypto.verify(record["signer_key"], crypto.canonical(manifest), record["signature"]))
        except (ValueError, KeyError, TypeError, UnicodeError):
            signature_ok = False
        signature_ms = milliseconds(start)
        history_ok = validate_history(self.history(record), evidence_id)
        passed = bool(hash_ok and signature_ok and history_ok)
        target = "vault" if candidate is None else "candidate"
        candidate_name = (secure_filename(candidate_name or "candidate.bin")[:180] or "candidate.bin") if candidate is not None else None
        failures = []
        if not storage_ok:
            failures.append(error)
        elif not hash_ok:
            if computed != manifest["sha256"]:
                failures.append("Candidate SHA-256 differs from the registered original." if candidate is not None else "Vault original SHA-256 differs from the registration manifest.")
            if len(data) != manifest["size_bytes"]:
                failures.append(f"File size differs: expected {manifest['size_bytes']:,} bytes, checked {len(data):,} bytes.")
        if not signature_ok:
            failures.append("The original handler signature or signing-key fingerprint is invalid.")
        if not history_ok:
            failures.append("A custody signature, sequence, or hash link is invalid.")
        error = " ".join(failures) if failures else None
        summary = ("The external candidate matches the registered original." if passed else "The external candidate failed comparison with the registered original.") if candidate is not None else ("The encrypted vault original passed every integrity check." if passed else "The encrypted vault original failed integrity verification.")
        if candidate is not None:
            summary += " The vault original was not modified; its current storage was not checked in this candidate comparison."
        analysis = {
            "summary": summary, "reason": error, "evidence_id": evidence_id, "target": target,
            "candidate_name": candidate_name, "failure_reasons": failures,
            "checks": [
                {"key": "hash", "label": "SHA-256 and byte count match", "status": "passed" if hash_ok else "failed",
                 "detail": "The checked bytes match the acquisition manifest." if hash_ok else (error if not storage_ok else "The checked bytes or byte count differ from the acquisition manifest.")},
                {"key": "handler_signature", "label": "Original handler signature", "status": "passed" if signature_ok else "failed",
                 "detail": "The signed registration manifest is valid." if signature_ok else "The signed registration manifest could not be validated."},
                {"key": "custody", "label": "Signed custody history", "status": "passed" if history_ok else "failed",
                 "detail": "Every custody signature, sequence and hash link is valid." if history_ok else "The custody chain contains an invalid signature, sequence or hash link."},
                {"key": "storage", "label": "External candidate readable" if candidate is not None else "Authenticated vault storage",
                 "status": "passed" if storage_ok else "failed",
                 "detail": "The uploaded candidate was read for comparison; the vault original was not read." if candidate is not None else ("The encrypted original was read and AES-GCM authentication passed." if storage_ok else error)},
            ],
        }
        result = {"evidence_id": evidence_id, "passed": passed, "hash_valid": bool(hash_ok), "signature_valid": bool(signature_ok),
                  "custody_valid": history_ok, "storage_valid": storage_ok, "expected_sha256": manifest["sha256"], "computed_sha256": computed,
                  "checked_at": now(), "target": target, "candidate_name": candidate_name, "analysis": analysis,
                  "expected_size_bytes": manifest["size_bytes"], "computed_size_bytes": len(data) if storage_ok else None,
                  "hash_ms": hash_ms, "signature_ms": signature_ms, "decryption_ms": decryption_ms,
                  "total_ms": milliseconds(total_start), "error": error}
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if candidate is None:
                db.execute("UPDATE evidence SET status=?,last_verified=? WHERE id=?", ("verified" if passed else "alert", now(), evidence_id))
            self._append(db, evidence_id, actor, "verified" if passed else "verification_failed", result)
            self._metric(db, evidence_id, "verification" if candidate is None else "candidate_verification", hash_ms, signature_ms, result["total_ms"], len(data), decryption_ms=decryption_ms)
            if not passed:
                db.execute("INSERT INTO alerts(evidence_id,message,created_at) VALUES(?,?,?)",
                    (evidence_id, error or ("Candidate differs from the registered original." if candidate is not None else "Evidence integrity, signature or custody check failed."), now()))
        return result

    def download(self, evidence_id, actor):
        result = self.verify_evidence(evidence_id, actor)
        if not result["passed"]:
            raise Problem("Evidence failed verification. Download is blocked.", 409)
        record = self.record(evidence_id)
        data = self._read(record)
        # Check the actual bytes returned, even if a file changed between reads.
        if crypto.digest(data) != record["manifest"]["sha256"]:
            raise Problem("Evidence changed during retrieval.", 409)
        self.log(evidence_id, actor, "downloaded", {"size_bytes": len(data)})
        return data, record["manifest"]["filename"]

    def add_peer(self, descriptor, url, token, actor):
        if not isinstance(descriptor, dict) or set(descriptor) != {"version", "node_id", "name", "signing_key", "encryption_key", "signature"}:
            raise Problem("Invalid node identity file.")
        body = {k: v for k, v in descriptor.items() if k != "signature"}
        try:
            expected_id = "NODE-" + crypto.fingerprint(descriptor["signing_key"])[:16].upper()
            crypto.load_public(descriptor["encryption_key"])
            valid = crypto.verify(descriptor["signing_key"], crypto.canonical(body), descriptor["signature"])
        except (ValueError, TypeError, UnicodeError):
            valid = False
            expected_id = None
        if not valid or descriptor["version"] != 1 or descriptor["node_id"] != expected_id:
            raise Problem("The node identity signature or key is invalid.")
        if descriptor["node_id"] == self.keys.node_id:
            raise Problem("Use the identity of a different node.")
        if not isinstance(descriptor["name"], str) or len(descriptor["name"]) > 120:
            raise Problem("Node name is invalid.")
        if url:
            self.validate_peer_url(url)
        protected_token = crypto.encrypt(self.keys.master, token.encode(), descriptor["node_id"].encode()) if token else None
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT node_id FROM peers WHERE node_id=?", (descriptor["node_id"],)).fetchone()
            if old:
                raise Problem("This node is already trusted. Its pinned identity cannot be silently replaced.", 409)
            db.execute("INSERT INTO peers(node_id,descriptor,url,token,added_at) VALUES(?,?,?,?,?)",
                (descriptor["node_id"], crypto.canonical(descriptor).decode(), url.rstrip("/"), protected_token, now()))
            self._append(db, None, actor, "peer_trusted", {"node_id": descriptor["node_id"], "signing_fingerprint": crypto.fingerprint(descriptor["signing_key"]), "encryption_fingerprint": crypto.fingerprint(descriptor["encryption_key"])})
        return descriptor["node_id"]

    def validate_peer_url(self, url):
        parsed = urlparse(url)
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"} or not parsed.hostname:
            raise Problem("Use a node base URL without credentials, path, query or fragment.")
        if parsed.scheme != "https" and not (self.allow_loopback and loopback and parsed.scheme == "http"):
            raise Problem("Peer URLs require HTTPS. HTTP is allowed only for an explicitly enabled loopback demo.")
        return parsed

    def update_peer(self, node_id, url, token, actor):
        if not isinstance(url, str):
            raise Problem("Delivery URL must be text.")
        url = url.strip().rstrip("/")
        if len(url) > 2048:
            raise Problem("Delivery URL must be no longer than 2048 characters.")
        if url:
            self.validate_peer_url(url)
        if token is not None and (not isinstance(token, str) or len(token) > 256):
            raise Problem("Receiver token must be text of up to 256 characters.")
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            peer = db.execute("SELECT token FROM peers WHERE node_id=?", (node_id,)).fetchone()
            if not peer:
                raise Problem("Trusted node not found.", 404)
            protected_token = peer["token"] if token is None else (
                crypto.encrypt(self.keys.master, token.encode(), node_id.encode()) if token else None
            )
            db.execute("UPDATE peers SET url=?,token=? WHERE node_id=?", (url, protected_token, node_id))
            self._append(db, None, actor, "peer_updated", {
                "node_id": node_id, "url": url, "token_changed": token is not None,
                "token_configured": bool(protected_token), "pinned_identity_retained": True,
            })
        return {"node_id": node_id, "url": url, "token_configured": bool(protected_token)}

    def peers(self):
        rows = self.db.rows("SELECT node_id,descriptor,url,added_at,(token IS NOT NULL) AS token_configured FROM peers ORDER BY added_at DESC")
        for row in rows:
            row["descriptor"] = json.loads(row["descriptor"])
            row["fingerprint"] = crypto.fingerprint(row["descriptor"]["signing_key"])
            row["token_configured"] = bool(row["token_configured"])
        return rows

    def export_package(self, evidence_id, peer_id, actor):
        start = time.perf_counter()
        if self.record(evidence_id)["archived"]:
            raise Problem("Restore this archived evidence record before preparing a transfer.", 409)
        peer = self.db.one("SELECT * FROM peers WHERE node_id=?", (peer_id,))
        if not peer:
            raise Problem("Choose a trusted receiving node.")
        result = self.verify_evidence(evidence_id, actor)
        if not result["passed"]:
            raise Problem("Evidence failed verification. Transfer is blocked.", 409)
        record = self.record(evidence_id)
        data, decryption_ms = self._read_timed(record)
        hash_start = time.perf_counter()
        if crypto.digest(data) != record["manifest"]["sha256"]:
            raise Problem("Evidence changed during transfer preparation.", 409)
        hash_ms = milliseconds(hash_start)
        package_id = str(uuid.uuid4())
        # Take the custody snapshot in the same transaction as its handoff event.
        # Concurrent views/checks cannot insert a new last event into this package.
        with self.db.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._append(db, evidence_id, actor, "transfer_prepared", {"package_id": package_id, "recipient": peer_id})
            local_history = [dict(row) for row in db.execute("SELECT * FROM events WHERE evidence_id=? ORDER BY id", (evidence_id,))]
            for event in local_history:
                event["payload"] = json.loads(event["payload"])
        payload = {"package_id": package_id, "created_at": now(), "manifest": record["manifest"], "evidence_signature": record["signature"],
                   "signer_key": record["signer_key"], "custody": record["imported_history"] + local_history, "content": crypto.b64(data)}
        descriptor = json.loads(peer["descriptor"])
        timings = {}
        package = crypto.canonical(crypto.seal(payload, descriptor["encryption_key"], peer_id, self.keys.node_id, self.keys.signing, timings=timings))
        elapsed = milliseconds(start)
        self._transfer(package_id, evidence_id, peer_id, "outbound", "prepared", len(package), elapsed, "Encrypted package prepared; delivery not yet confirmed.", encryption_ms=timings["encryption_ms"])
        with self.db.connect() as db:
            self._metric(db, evidence_id, "transfer_preparation", hash_ms, timings["signature_ms"], elapsed, len(data), encryption_ms=timings["encryption_ms"], decryption_ms=decryption_ms)
        return package, package_id

    def _transfer(self, package_id, evidence_id, peer_id, direction, status, size, elapsed, detail, encryption_ms=None, decryption_ms=None):
        with self.db.connect() as db:
            db.execute("INSERT INTO transfers(id,evidence_id,peer_id,direction,status,bytes,elapsed_ms,created_at,detail,encryption_ms,decryption_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (package_id, evidence_id, peer_id, direction, status, size, elapsed, now(), detail, encryption_ms, decryption_ms))

    def receive_package(self, raw, actor):
        start = time.perf_counter()
        evidence_id = package_id = path = None
        definitions = [
            ("package_size", "Package size limit"), ("structure", "Package format and structure"),
            ("recipient", "Addressed to this node"), ("trusted_sender", "Trusted sending node"),
            ("sender_signature", "Sending node package signature"), ("decryption", "Authenticated package decryption"),
            ("payload", "Decrypted payload structure"), ("manifest", "Original evidence manifest"),
            ("file_size", "Evidence file size limit"), ("hash", "Original file SHA-256 and size"),
            ("handler_signature", "Original handler signature"), ("custody", "Signed custody and handoff history"),
            ("replay", "Duplicate and replay protection"), ("storage", "Encrypted vault registration"),
        ]
        checks = [{"key": key, "label": label, "status": "not_checked", "detail": "This check has not run."} for key, label in definitions]
        by_key = {item["key"]: item for item in checks}
        stage = "package_size"

        def passed(key, detail):
            by_key[key].update(status="passed", detail=detail)

        def reject(message, status=400):
            raise Problem(message, status)

        generic = {
            "structure": "The package is not valid JSON or has an invalid envelope structure.",
            "decryption": "The encrypted package could not be authenticated or decrypted. Its key or ciphertext may be damaged.",
            "payload": "The decrypted package has invalid content or metadata fields.",
            "manifest": "The original evidence manifest is invalid.",
            "file_size": "The package contains invalid or oversized evidence content.",
            "hash": "Transferred file hash or size differs from the registered original.",
            "handler_signature": "The original handler key or signature is invalid.",
            "custody": "The signed custody history or sender handoff is invalid.",
            "storage": "The verified package could not be saved to the encrypted vault.",
        }
        try:
            if len(raw) > self.max_package_size:
                reject("The encrypted package exceeds this node's package size limit.", 413)
            passed(stage, f"Package contains {len(raw):,} bytes; limit is {self.max_package_size:,} bytes.")

            stage = "structure"
            envelope = json.loads(raw)
            expected = {"format", "version", "recipient", "sender", "wrapped_key", "ciphertext", "signature"}
            if (not isinstance(envelope, dict) or set(envelope) != expected
                or any(not isinstance(envelope[field], str) for field in expected - {"version"})
                or envelope["format"] != "securechain-envelope" or envelope["version"] != 1):
                reject("Invalid transfer envelope format, version, or fields.")
            passed(stage, "SecureChain envelope format, version and fields are valid.")

            stage = "recipient"
            if envelope["recipient"] != self.keys.node_id:
                reject("This package is not addressed to this node.")
            passed(stage, "The encrypted package is addressed to this receiving node.")

            stage = "trusted_sender"
            peer = self.db.one("SELECT descriptor FROM peers WHERE node_id=?", (envelope["sender"],))
            if not peer:
                reject("Sender is not a trusted peer.", 403)
            descriptor = json.loads(peer["descriptor"])
            passed(stage, "The sending node has a pinned trusted identity on this node.")

            stage = "sender_signature"
            body = {key: value for key, value in envelope.items() if key != "signature"}
            signature_start = time.perf_counter()
            if not crypto.verify(descriptor["signing_key"], crypto.canonical(body), envelope["signature"]):
                reject("Sending node signature is invalid. The package was changed or was not signed by the trusted sender.")
            signature_ms = milliseconds(signature_start)
            passed(stage, "The package signature matches the trusted sender's pinned key.")

            stage = "decryption"
            wrapped_key, ciphertext = crypto.unb64(envelope["wrapped_key"]), crypto.unb64(envelope["ciphertext"])
            header = {field: envelope[field] for field in ("format", "version", "recipient", "sender")}
            aad = crypto.canonical(header)
            decryption_start = time.perf_counter()
            key = self.keys.encryption.decrypt(wrapped_key, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            plaintext = crypto.decrypt(key, ciphertext, aad)
            decryption_ms = milliseconds(decryption_start)
            passed(stage, "The recipient key opened the package and AES-GCM authentication passed.")

            stage = "payload"
            payload = json.loads(plaintext)
            payload_fields = {"package_id", "created_at", "manifest", "evidence_signature", "signer_key", "custody", "content"}
            if (not isinstance(payload, dict) or set(payload) != payload_fields
                or any(not isinstance(payload[field], str) for field in {"package_id", "created_at", "evidence_signature", "signer_key", "content"})
                or not isinstance(payload["custody"], list)):
                reject("The decrypted package payload has invalid fields.")
            package_id = str(uuid.UUID(payload["package_id"]))
            passed(stage, "Payload fields and package identifier are valid.")

            stage = "manifest"
            manifest = payload["manifest"]
            self._validate_manifest(manifest)
            evidence_id = manifest["evidence_id"]
            passed(stage, "The acquisition manifest contains valid evidence metadata.")

            stage = "file_size"
            if manifest["size_bytes"] > self.max_file_size:
                reject("Package exceeds the evidence file limit.", 413)
            data = crypto.unb64(payload["content"])
            if len(data) > self.max_file_size:
                reject("Package exceeds the evidence file limit.", 413)
            passed(stage, f"Evidence contains {len(data):,} bytes; limit is {self.max_file_size:,} bytes.")

            stage = "hash"
            hash_start = time.perf_counter()
            computed = crypto.digest(data)
            hash_ms = milliseconds(hash_start)
            by_key[stage].update(expected_sha256=manifest["sha256"], computed_sha256=computed,
                                 expected_size_bytes=manifest["size_bytes"], computed_size_bytes=len(data))
            if computed != manifest["sha256"] or len(data) != manifest["size_bytes"]:
                reject("Transferred file SHA-256 or size differs from the registered original.")
            passed(stage, "The decrypted evidence SHA-256 and byte count match the registered original.")

            stage = "handler_signature"
            signature_start = time.perf_counter()
            if (crypto.fingerprint(payload["signer_key"]) != manifest["signer_fingerprint"]
                or not crypto.verify(payload["signer_key"], crypto.canonical(manifest), payload["evidence_signature"])):
                reject("Original handler signature is invalid.")
            signature_ms += milliseconds(signature_start)
            passed(stage, "The original handler signature validates the acquisition manifest.")

            stage = "custody"
            if not payload["custody"] or not validate_history(payload["custody"], evidence_id):
                reject("Custody history signatures, sequence, or hash links are invalid.")
            first = payload["custody"][0]["payload"]
            if (first["node_id"] != manifest["origin_node"] or first["action"] != "registered"
                or first["actor"] != manifest["handler"] or first["detail"].get("sha256") != manifest["sha256"]):
                reject("Custody history does not start with the original acquisition.")
            last = payload["custody"][-1]["payload"]
            if (last["node_id"] != envelope["sender"] or last["action"] != "transfer_prepared"
                or last["detail"].get("recipient") != self.keys.node_id
                or last["detail"].get("package_id") != payload["package_id"]):
                reject("Transfer does not match the sender's signed custody handoff.")
            passed(stage, "Every custody signature and hash link is valid; acquisition and handoff match this transfer.")

            stage = "replay"
            with self.db.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT package_id FROM receipts WHERE package_id=?", (package_id,)).fetchone():
                    reject("This package has already been received. Replay rejected.", 409)
                if db.execute("SELECT id FROM evidence WHERE id=?", (evidence_id,)).fetchone():
                    reject("This evidence ID is already registered on this node.", 409)
                passed(stage, "This package and evidence identifier have not been received before.")
                stage = "storage"
                blob_name = uuid.uuid4().hex + ".enc"
                path = self.vault / blob_name
                encryption_start = time.perf_counter()
                encrypted = crypto.encrypt(self.keys.master, data, evidence_id.encode())
                encryption_ms = milliseconds(encryption_start)
                crypto.write_secret(path, encrypted)
                db.execute("INSERT INTO evidence(id,manifest,signature,signer_key,blob_name,imported_history,status,last_verified,registered_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (evidence_id, crypto.canonical(manifest).decode(), payload["evidence_signature"], payload["signer_key"], blob_name, crypto.canonical(payload["custody"]).decode(), "verified", now(), now()))
                db.execute("INSERT INTO receipts VALUES(?,?,?)", (package_id, evidence_id, now()))
                self._append(db, evidence_id, actor, "received", {"sender": envelope["sender"], "package_id": package_id,
                    "hash_valid": True, "signature_valid": True, "custody_valid": True, "sender_signature_valid": True})
                elapsed = milliseconds(start)
                db.execute("INSERT INTO transfers(id,evidence_id,peer_id,direction,status,bytes,elapsed_ms,created_at,detail,decryption_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (package_id, evidence_id, envelope["sender"], "inbound", "received", len(raw), elapsed, now(), "Hash, handler signature, sender signature and custody validated.", decryption_ms))
                self._metric(db, evidence_id, "package_receive", hash_ms, signature_ms, elapsed, len(data), encryption_ms=encryption_ms, decryption_ms=decryption_ms)
            passed(stage, "The original was registered in encrypted storage and the receipt was recorded.")
        except (Problem, KeyError, TypeError, ValueError, InvalidTag, UnicodeError, AttributeError, OSError) as exc:
            if path is not None:
                path.unlink(missing_ok=True)
            message = str(exc) if isinstance(exc, Problem) else generic.get(stage, "The transfer package failed validation.")
            status = exc.status if isinstance(exc, Problem) else (500 if stage == "storage" else 400)
            by_key[stage].update(status="failed", detail=message)
            analysis = {"stage": stage, "reason": message, "summary": "Package rejected. No evidence was added to the vault.",
                        "evidence_id": evidence_id, "package_id": package_id, "checks": checks, "checked_at": now()}
            self.alert(evidence_id, f"Transfer rejected: {message}")
            self.log(None, actor, "transfer_rejected", analysis)
            raise Problem(message, status, analysis) from exc
        except Exception:
            if path is not None:
                path.unlink(missing_ok=True)
            raise
        receipt = {"package_id": package_id, "evidence_id": evidence_id, "receiver": self.keys.node_id, "sha256": manifest["sha256"], "received_at": now()}
        return {**receipt, "signature": crypto.sign(self.keys.signing, crypto.canonical(receipt))}

    def _validate_manifest(self, manifest):
        fields = {"version", "evidence_id", "filename", "size_bytes", "sha256", "mime_type", "case_id", "source", "source_kind", "usb_serial", "description", "acquired_at", "registered_at", "handler", "handler_name", "origin_node", "signer_fingerprint"}
        if not isinstance(manifest, dict) or set(manifest) != fields or manifest["version"] != 1:
            raise Problem("Invalid evidence manifest.")
        if not isinstance(manifest["size_bytes"], int) or manifest["size_bytes"] < 0:
            raise Problem("Invalid evidence size.")
        for field in fields - {"version", "size_bytes"}:
            if not isinstance(manifest[field], str) or len(manifest[field]) > 2000:
                raise Problem("Invalid evidence metadata.")
        if not manifest["evidence_id"].startswith("SC-") or len(manifest["evidence_id"]) != 19 or any(c not in "0123456789ABCDEF" for c in manifest["evidence_id"][3:]):
            raise Problem("Invalid evidence ID.")
        if len(manifest["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in manifest["sha256"]):
            raise Problem("Invalid evidence digest.")
        if not manifest["filename"] or secure_filename(manifest["filename"]) != manifest["filename"]:
            raise Problem("Invalid evidence filename.")

    def send_package(self, evidence_id, peer_id, actor):
        peer = self.db.one("SELECT * FROM peers WHERE node_id=?", (peer_id,))
        if not peer or not peer["url"]:
            raise Problem("This peer has no delivery URL. Export a package or add a peer with a URL.")
        self.validate_peer_url(peer["url"])
        package, package_id = self.export_package(evidence_id, peer_id, actor)
        start = time.perf_counter()
        headers = {"Content-Type": "application/json"}
        if peer["token"]:
            token = crypto.decrypt(self.keys.master, peer["token"], peer_id.encode()).decode()
            headers["Authorization"] = "Bearer " + token
        try:
            response = requests.post(peer["url"] + "/api/node/receive", data=package, headers=headers, timeout=(5, 60), allow_redirects=False)
            if response.status_code != 201:
                raise Problem(f"Receiver declined delivery (HTTP {response.status_code}).", 502)
            receipt = response.json()
            if not isinstance(receipt, dict):
                raise Problem("Receiver returned an invalid receipt.", 502)
            signature = receipt.pop("signature", "")
            descriptor = json.loads(peer["descriptor"])
            if (receipt.get("package_id") != package_id or receipt.get("evidence_id") != evidence_id or receipt.get("receiver") != peer_id
                or receipt.get("sha256") != self.record(evidence_id)["manifest"]["sha256"]
                or not crypto.verify(descriptor["signing_key"], crypto.canonical(receipt), signature)):
                raise Problem("Receiver receipt signature is invalid.", 502)
            status, detail = "delivered", "Receiving node returned a verified, signed receipt."
        except (requests.RequestException, ValueError, Problem) as exc:
            elapsed = milliseconds(start)
            with self.db.connect() as db:
                db.execute("UPDATE transfers SET status='failed',elapsed_ms=?,detail=? WHERE id=?", (elapsed, str(exc)[:500], package_id))
            self.log(evidence_id, actor, "transfer_failed", {
                "package_id": package_id, "recipient": peer_id, "recipient_url": peer["url"],
                "delivery": "unconfirmed", "reason": str(exc)[:500], "elapsed_ms": elapsed,
            })
            raise Problem("Delivery could not be confirmed. Check receiver logs before retrying.", 502) from exc
        elapsed = milliseconds(start)
        with self.db.connect() as db:
            db.execute("UPDATE transfers SET status=?,elapsed_ms=?,detail=? WHERE id=?", (status, elapsed, detail, package_id))
        self.log(evidence_id, actor, "transferred", {"package_id": package_id, "recipient": peer_id, "receipt": {**receipt, "signature": signature}, "elapsed_ms": elapsed})
        return {"package_id": package_id, "status": status, "bytes": len(package), "elapsed_ms": elapsed}

    def report(self, evidence_id, actor):
        result = self.verify_evidence(evidence_id, actor)
        self.log(evidence_id, actor, "report_generated", {"format": "signed-json"})
        record = self.record(evidence_id)
        report = {"format": "securechain-verification-report", "version": 1, "generated_at": now(), "generated_by": actor,
                  "node": self.keys.descriptor(self.name), "manifest": record["manifest"], "evidence_signature": record["signature"],
                  "signer_key": record["signer_key"], "verification": result, "custody": self.history(record)}
        return {**report, "report_signature": crypto.sign(self.keys.signing, crypto.canonical(report))}

    def summary(self):
        evidence = self.list_evidence()
        archived_evidence = self.list_evidence(archived=True)
        events = self.events(all_events=True)
        return {"node": self.keys.descriptor(self.name), "evidence": evidence, "archived_evidence": archived_evidence,
                "processing_metrics_version": 2,
                "events": list(reversed(events[-100:])), "peers": self.peers(),
                "alerts": self.db.rows("SELECT * FROM alerts ORDER BY id DESC LIMIT 100"),
                "transfers": self.db.rows("SELECT * FROM transfers ORDER BY created_at DESC LIMIT 100"),
                "metrics": self.db.rows("SELECT * FROM metrics ORDER BY id DESC LIMIT 200"),
                "stats": {"total": len(evidence), "archived": len(archived_evidence), "verified": sum(row["status"] == "verified" for row in evidence),
                          "alerts": self.db.one("SELECT COUNT(*) AS count FROM alerts WHERE acknowledged=0")["count"],
                          "transfers": self.db.one("SELECT COUNT(*) AS count FROM transfers")["count"], "audit_valid": validate_history(events)},
                "max_file_size": self.max_file_size, "max_package_size": self.max_package_size}
