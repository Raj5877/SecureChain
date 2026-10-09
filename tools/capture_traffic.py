"""Capture only traffic on the interface/filter explicitly selected by the user."""
import argparse
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Capture SecureChain transfer traffic with PyShark/TShark")
    parser.add_argument("--interface", required=True, help="TShark interface name or number (see tshark -D)")
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--filter", default="tcp port 5000 or tcp port 5001", help="BPF capture filter")
    parser.add_argument("--output", required=True, help="New .pcapng file path")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error("--seconds must be between 1 and 3600")
    if Path(args.output).exists():
        parser.error("The output file already exists; select a new path")
    try:
        import pyshark
    except ImportError:
        sys.exit("Install optional traffic dependencies: python -m pip install -r requirements-traffic.txt. Wireshark/TShark is also required.")
    capture = None
    try:
        capture = pyshark.LiveCapture(interface=args.interface, bpf_filter=args.filter, output_file=args.output)
        print(f"Capturing {args.interface} for {args.seconds}s with filter {args.filter!r}. Start your transfer now.")
        capture.sniff(timeout=args.seconds)
        print(f"Capture saved to {args.output}")
    except Exception as exc:
        sys.exit(f"Capture failed: {exc}. Check TShark installation, interface name and capture permissions.")
    finally:
        if capture is not None:
            capture.close()


if __name__ == "__main__":
    main()
