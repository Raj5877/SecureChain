"""Locate an installed TShark executable without changing the system."""
import os
import shutil
import re
import subprocess
from pathlib import Path


INSTALL_GUIDANCE = (
    "Install Wireshark from https://www.wireshark.org/download.html "
    "with the TShark component selected. On Windows, install Npcap "
    "for live capture. PyShark's pip package does not install TShark.\n"
    "If Wireshark is already installed, supply --tshark-path "
    '"C:\\Program Files\\Wireshark\\tshark.exe" or set TSHARK_PATH.\n'
    "List capture interfaces in PowerShell with:\n"
    '& "C:\\Program Files\\Wireshark\\tshark.exe" -D'
)


def _executable_at(value):
    path = Path(os.path.expandvars(str(value))).expanduser()
    executable_name = "tshark.exe" if os.name == "nt" else "tshark"
    if path.is_dir():
        path = path / executable_name
    if path.name.lower() != executable_name:
        return None
    if path.is_file() and (os.name == "nt" or os.access(path, os.X_OK)):
        return str(path.resolve())
    return None


def resolve_tshark(explicit_path=None):
    """Prefer a supplied path, then TSHARK_PATH, PATH, and Windows defaults."""
    if explicit_path is not None:
        configured = explicit_path
        source = "--tshark-path"
    else:
        configured = os.environ.get("TSHARK_PATH")
        source = "TSHARK_PATH"

    if configured:
        resolved = _executable_at(configured)
        if resolved:
            return resolved
        raise FileNotFoundError(
            f"{source} does not point to an installed TShark executable: "
            f"{configured}\n{INSTALL_GUIDANCE}"
        )
    if explicit_path is not None:
        raise FileNotFoundError(f"--tshark-path is empty.\n{INSTALL_GUIDANCE}")

    on_path = shutil.which("tshark")
    if on_path:
        resolved = _executable_at(on_path)
        if resolved:
            return resolved

    if os.name == "nt":
        roots = [
            os.environ.get("ProgramW6432"),
            os.environ.get("ProgramFiles"),
            os.environ.get("ProgramFiles(x86)"),
            os.environ.get("SystemDrive", "C:") + "/Program Files",
            os.environ.get("SystemDrive", "C:") + "/Program Files (x86)",
        ]
        for root in dict.fromkeys(root for root in roots if root):
            resolved = _executable_at(Path(root) / "Wireshark" / "tshark.exe")
            if resolved:
                return resolved

    raise FileNotFoundError(f"TShark was not found.\n{INSTALL_GUIDANCE}")


def resolve_capture_interface(interface, tshark_path):
    """Resolve today's interface number, or a stable loopback alias, to its name."""
    result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True,
                            check=True, timeout=15)
    entries = []
    for line in result.stdout.splitlines():
        match = re.match(r"^(\d+)\.\s+(.*?)(?:\s+\((.*)\))?$", line.strip())
        if match:
            entries.append(match.groups())
    requested = interface.strip()
    for number, name, description in entries:
        loopback = name.casefold() in {r"\device\npf_loopback", "lo", "lo0"}
        if (requested == number or requested.casefold() == name.casefold()
                or (requested.casefold() == "loopback" and loopback)):
            return name, description or name
    raise ValueError("Capture interface not found. Run tshark -D for the current list; use --interface loopback for localhost traffic.")
