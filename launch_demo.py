"""Run two local nodes without preloaded evidence or automatic transfers."""
import argparse
import threading
import time
from pathlib import Path

from werkzeug.serving import make_server

from securechain import create_app

DEMO_USERNAME = "demo"
DEMO_PASSWORD = "SecureChain-demo-2026!"


def configure_nodes(sender, receiver):
    for service in (sender, receiver):
        if not service.db.one("SELECT id FROM users LIMIT 1"):
            service.create_user(DEMO_USERNAME, "Demo Investigator", DEMO_PASSWORD, "admin", initial=True)
    if not sender.peers():
        sender.add_peer(receiver.keys.descriptor(receiver.name), "http://127.0.0.1:5001", "", DEMO_USERNAME)
    if not receiver.peers():
        receiver.add_peer(sender.keys.descriptor(sender.name), "http://127.0.0.1:5000", "", DEMO_USERNAME)


def main():
    parser = argparse.ArgumentParser(description="Start the two-node SecureChain classroom demo")
    parser.add_argument("--data-dir", default="demo-data")
    args = parser.parse_args()
    root = Path(args.data_dir)
    sender_app = create_app({"DATA_DIR": root / "sender", "NODE_NAME": "Sender Lab · Demo", "ALLOW_LOOPBACK_HTTP": True})
    receiver_app = create_app({"DATA_DIR": root / "receiver", "NODE_NAME": "Receiver Lab · Demo", "ALLOW_LOOPBACK_HTTP": True})
    sender = sender_app.extensions["securechain"]
    receiver = receiver_app.extensions["securechain"]
    configure_nodes(sender, receiver)
    servers = []
    try:
        for app, port in ((sender_app, 5000), (receiver_app, 5001)):
            server = make_server("127.0.0.1", port, app, threaded=True)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        print("\nSecureChain two-node demo is running.", flush=True)
        print("Sender:   http://127.0.0.1:5000", flush=True)
        print("Receiver: http://127.0.0.1:5001", flush=True)
        print(f"Username: {DEMO_USERNAME}\nPassword: {DEMO_PASSWORD}", flush=True)
        print("No sample evidence is loaded. Register your own files to begin.", flush=True)
        print("Transfers and verification checks run only when you request them.", flush=True)
        print("Press Ctrl+C to stop both nodes. Demo data is retained for your next session.\n", flush=True)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping demo nodes.", flush=True)
    finally:
        for server in servers:
            server.shutdown()


if __name__ == "__main__":
    main()
