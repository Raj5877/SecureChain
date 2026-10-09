"""Capture only traffic on the interface/filter explicitly selected by the user."""
import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .tshark_support import resolve_tshark, resolve_capture_interface
else:
    from tshark_support import resolve_tshark, resolve_capture_interface


def main():
    parser = argparse.ArgumentParser(description="Capture SecureChain transfer traffic with TShark")
    parser.add_argument("--interface", required=True, help="Interface name, current number, or loopback for localhost traffic (numbers can change; see tshark -D)")
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--filter", default="tcp port 5000 or tcp port 5001", help="BPF capture filter")
    parser.add_argument("--output", help="Filename in captures/; default: unique timestamped name. Explicit directory paths are supported.")
    parser.add_argument("--tshark-path", help="Path to tshark.exe (also supports the TSHARK_PATH environment variable)")
    args = parser.parse_args()
    if not 1 <= args.seconds <= 3600:
        parser.error("--seconds must be between 1 and 3600")
    capture_directory = Path(__file__).resolve().parent.parent / "captures"
    output = Path(args.output) if args.output else Path(datetime.now(timezone.utc).strftime("capture-%Y%m%dT%H%M%S-%fZ.pcapng"))
    if not output.is_absolute() and output.parent == Path("."):
        output = capture_directory / output
    output = output.resolve()
    if output.exists():
        parser.error("The output file already exists; select a new path")
    try:
        tshark_path = resolve_tshark(args.tshark_path)
        interface, interface_description = resolve_capture_interface(args.interface, tshark_path)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    except Exception as exc:
        parser.error(f"Could not list capture interfaces: {exc}")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        print(f"Capturing {interface_description} ({interface}) for {args.seconds}s with filter {args.filter!r}. Start your transfer now.", flush=True)
        print(f"Saving to {output}", flush=True)
        # Let TShark stop and finalize the file itself. PyShark's live capture
        # leaves asyncio pipe transports unclosed on Windows at shutdown.
        subprocess.run([tshark_path, "-i", interface, "-f", args.filter,
                        "-a", f"duration:{args.seconds}", "-w", str(output),
                        "-F", "pcapng", "-q"], check=True)
        print(f"Capture saved to {output}")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"Capture failed: TShark exited with status {exc.returncode}. Check the diagnostic above, interface and capture permissions.")
    except Exception as exc:
        sys.exit(f"Capture failed: {exc}. Check TShark installation, interface name and capture permissions.")


if __name__ == "__main__":
    main()
