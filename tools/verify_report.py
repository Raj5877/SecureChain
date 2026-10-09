"""Offline verification of a report with an independently trusted node identity."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from securechain import crypto
from securechain.service import validate_history


def verify_report(report, identity):
    try:
        body = {k: v for k, v in report.items() if k != "report_signature"}
        manifest = report["manifest"]
        return (report["format"] == "securechain-verification-report" and report["version"] == 1
            and all(report["node"][field] == identity[field] for field in ("node_id", "signing_key", "encryption_key"))
            and crypto.verify(identity["signing_key"], crypto.canonical(body), report["report_signature"])
            and crypto.fingerprint(report["signer_key"]) == manifest["signer_fingerprint"]
            and crypto.verify(report["signer_key"], crypto.canonical(manifest), report["evidence_signature"])
            and validate_history(report["custody"], manifest["evidence_id"]))
    except (KeyError, TypeError, ValueError):
        return False


def main():
    parser = argparse.ArgumentParser(description="Verify a signed SecureChain report offline")
    parser.add_argument("report")
    parser.add_argument("--identity", required=True, help="Independently trusted reporting-node identity JSON")
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    identity = json.loads(Path(args.identity).read_text(encoding="utf-8"))
    if not verify_report(report, identity):
        sys.exit("INVALID: report signatures or custody history failed verification.")
    verification = report["verification"]
    print("VALID: reporting-node signature, acquisition signature and custody links verified.")
    print(f"Recorded vault verification: {'PASSED' if verification['passed'] else 'FAILED'} at {verification['checked_at']}")
    print("This proves report authenticity. Rehash the actual evidence file to independently verify its content.")


if __name__ == "__main__":
    main()
