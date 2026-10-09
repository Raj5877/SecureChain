"""Summarize real PCAP/PCAPNG traffic. TLS presence is an observation, not proof."""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

if __package__:
    from .tshark_support import resolve_tshark
else:
    from tshark_support import resolve_tshark


def summarize_packets(packets):
    count = total_bytes = tls_packets = retransmissions = 0
    protocols = Counter()
    first = last = None
    for packet in packets:
        timestamp = float(packet.sniff_timestamp)
        first = timestamp if first is None else min(first, timestamp)
        last = timestamp if last is None else max(last, timestamp)
        count += 1
        total_bytes += int(packet.length)
        protocols[packet.highest_layer] += 1
        if any(layer.layer_name == "tls" for layer in packet.layers):
            tls_packets += 1
        if hasattr(packet, "tcp") and (hasattr(packet.tcp, "analysis_retransmission") or hasattr(packet.tcp, "analysis_fast_retransmission")):
            retransmissions += 1
    duration = last - first if first is not None else 0
    return {"packet_count": count, "captured_bytes": total_bytes, "duration_seconds": round(duration, 6),
            "average_packet_bytes": round(total_bytes / count, 2) if count else 0,
            "throughput_mbps": round(total_bytes * 8 / duration / 1_000_000, 6) if duration > 0 else 0,
            "protocols": dict(protocols), "tls_packets": tls_packets, "tcp_retransmissions": retransmissions,
            "interpretation": "Observed TLS packets do not prove certificate validation or payload confidentiality. Local HTTP demos use encrypted envelopes but do not provide TLS transport security."}


def main():
    parser = argparse.ArgumentParser(description="Analyze captured SecureChain traffic")
    parser.add_argument("capture", help="PCAP or PCAPNG path, or a filename in captures/")
    parser.add_argument("--output", help="Optional JSON summary filename in captures/, or an explicit directory path")
    parser.add_argument("--display-filter", default="tcp.port == 5000 || tcp.port == 5001")
    parser.add_argument("--tshark-path", help="Path to tshark.exe (also supports the TSHARK_PATH environment variable)")
    args = parser.parse_args()
    capture_directory = Path(__file__).resolve().parent.parent / "captures"
    input_path = Path(args.capture)
    if not input_path.is_absolute() and input_path.parent == Path(".") and (capture_directory / input_path).is_file():
        input_path = capture_directory / input_path
    if not input_path.is_file():
        parser.error("Capture file does not exist")
    input_path = input_path.resolve()
    try:
        tshark_path = resolve_tshark(args.tshark_path)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    try:
        import pyshark
    except ImportError:
        sys.exit("Install optional traffic dependencies: python -m pip install -r requirements-traffic.txt. Wireshark/TShark is also required.")
    capture = None
    try:
        capture = pyshark.FileCapture(str(input_path), display_filter=args.display_filter, keep_packets=False, tshark_path=tshark_path)
        summary = summarize_packets(capture)
        summary["capture"] = str(input_path)
        summary["display_filter"] = args.display_filter
    except Exception as exc:
        sys.exit(f"Analysis failed: {exc}. Check TShark installation and capture format.")
    finally:
        if capture is not None:
            capture.close()
    output = json.dumps(summary, indent=2)
    print(output)
    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute() and output_path.parent == Path("."):
            output_path = capture_directory / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
        print(f"Summary saved to {output_path.resolve()}")


if __name__ == "__main__":
    main()
