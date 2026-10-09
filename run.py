"""Local development entry point. Use Waitress behind HTTPS for deployed nodes."""
import argparse
from securechain import create_app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a SecureChain node")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--name", default=None)
    parser.add_argument("--allow-loopback-http", action="store_true", help="Enable HTTP peer URLs on localhost only")
    parser.add_argument("--cert", help="TLS certificate PEM file")
    parser.add_argument("--key", help="TLS private key PEM file")
    args = parser.parse_args()
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")
    config = {}
    if args.data_dir:
        config["DATA_DIR"] = args.data_dir
    if args.name:
        config["NODE_NAME"] = args.name
    if args.allow_loopback_http:
        config["ALLOW_LOOPBACK_HTTP"] = True
    if args.cert:
        config["SESSION_COOKIE_SECURE"] = True
    app = create_app(config)
    app.run(host=args.host, port=args.port, debug=False, ssl_context=(args.cert, args.key) if args.cert else None)
