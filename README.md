# SecureChain

SecureChain implements the **Digital Evidence Chain-of-Custody & Integrity Verification Framework** described in `SecureChain_Synopsis.docx`. It provides a Flask web application, encrypted evidence vault, SQLite database, signed custody records, recipient-bound transfers, verification reports, and optional Wireshark/PyShark tools.

## Run the demonstration

Python 3.11 or newer is required. From this project folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe launch_demo.py
```

On Windows, after installing the dependencies, you can also double-click **Start-SecureChain.cmd**.

| Node | Address |
| --- | --- |
| Sender | http://127.0.0.1:5000 |
| Receiver | http://127.0.0.1:5001 |

Both demo nodes use username **`demo`** and password **`SecureChain-demo-2026!`**. These credentials are for the local demonstration only. Both servers bind to loopback.

The launcher opens empty evidence workspaces and connects the two trusted nodes. It creates no sample files, alerts, or automatic transfers. The sender and receiver have independent databases, encryption keys, and node identities. Your accounts, connections, and any evidence you register persist under `demo-data/` between launches.

## Run a clean investigation node

```powershell
.\.venv\Scripts\python.exe run.py --name "Investigation Lab" --data-dir instance --port 5002
```

Open http://127.0.0.1:5002 and create the initial administrator. There are no default accounts on a clean node. Passwords require at least 12 characters.

In **Node settings**, administrators can create investigator or viewer accounts. Investigators acquire, verify, and transfer evidence. Viewers inspect evidence, retrieve verified originals, and export reports. All authorized users share the node's evidence workspace; case-level isolation is outside this implementation.

## Manual feature walkthrough

1. Sign in to the sender and register your own file with a case reference, source, acquisition time, and optional USB identifier. Any binary format is accepted, including documents, images, audio, and video, up to **32 MB**.
2. Open **Evidence vault** and select the registered file to inspect its manifest, original hash, handler, acquisition source, and custody history.
3. Choose **Verify integrity**, leave the candidate field empty, and run verification. This decrypts and authenticates the stored original, recomputes SHA-256, verifies its RSA signature, and validates custody links.
4. Change a separate copy of that file. Upload it in the verification dialog. The failed comparison generates an alert and custody event; the registered original stays intact.
5. Choose **Transfer**, select the receiving node, and send directly. The receiver checks the sender signature, decrypts the package, validates the original hash, handler signature, and custody history, and returns a signed receipt. Only a validated receipt marks the sender transfer as delivered.
6. Alternatively, export an encrypted `.scpkg` package and upload it using **Receive package** on the receiver. A second upload of the same package is rejected as a replay. Offline export stays marked **Prepared** because no network receipt was received.
7. Download a **Signed report** from the evidence record or a complete signed local audit from **Audit log**. Export CSV processing measurements from **Analytics**.

Registration preserves the supplied file bytes. USB acquisition is a **logical file acquisition**: obtain the file using your forensic procedure, then register that file and the source identifier. SecureChain does not image physical disks, recover deleted files, or provide a hardware write blocker.

## Connect two real devices

Run each node with its own data directory, port, and TLS certificate:

```powershell
.\.venv\Scripts\python.exe run.py --host 0.0.0.0 --port 5000 --name "Sender Lab" --data-dir sender-data --cert sender-cert.pem --key sender-key.pem
.\.venv\Scripts\python.exe run.py --host 0.0.0.0 --port 5001 --name "Receiver Lab" --data-dir receiver-data --cert receiver-cert.pem --key receiver-key.pem
```

Use certificates trusted by the browsers and Python requests on both devices. The certificate names must match the peer hostnames. Certificate verification is enabled; redirects are not followed. For an institutional/private CA, set `REQUESTS_CA_BUNDLE` to that CA's PEM bundle on the sending system.

Download each public identity in **Node settings**. On the opposite node, choose **Trust a node**, upload that identity, and independently compare **both** SHA-256 key fingerprints through a trusted channel. The self-signature validates possession of the signing key; the out-of-band fingerprint comparison establishes who the node belongs to. Add the HTTPS base URL if direct delivery is required. Both nodes must trust each other for bidirectional exchange.

An optional `SECURECHAIN_RECEIVE_TOKEN` adds a bearer-token requirement to the direct receive endpoint. Configure the matching token when adding that receiver as a peer. Package import and direct receive always require an authenticated package signature from a pinned peer.

HTTP peer URLs are rejected except loopback URLs when `--allow-loopback-http` is explicitly supplied. The classroom launcher enables that exception. Its evidence envelopes remain encrypted and signed, but localhost HTTP does not provide TLS transport protection.

For deployment, use a WSGI server behind a correctly configured HTTPS reverse proxy. The included development launcher is intended for the lab demonstration:

```powershell
$env:SECURECHAIN_DATA_DIR = "C:\securechain-data\lab"
$env:SECURECHAIN_NODE_NAME = "Investigation Lab"
$env:SECURECHAIN_SECURE_COOKIES = "1"
.\.venv\Scripts\waitress-serve.exe --listen=127.0.0.1:8000 wsgi:app
```

## Cryptography and custody design

| Requirement from the synopsis | Implementation |
| --- | --- |
| Unique evidence registration | Random `SC-` IDs and immutable acquisition manifests |
| SHA-256 integrity | Exact-byte hashing at registration, retrieval, verification, export, and reception |
| RSA digital signatures | Individual RSA-3072 handler keys sign canonical acquisition manifests with RSA-PSS/SHA-256 |
| User authentication | Scrypt password hashes, signed sessions, CSRF tokens, roles, sign-in rate limiting |
| Storage confidentiality | AES-256-GCM encrypted files with evidence ID bound as associated data |
| Chronological custody | UTC event times, handler names, per-evidence sequence numbers, previous-event hashes, RSA node signatures |
| Secure two-system transfer | Fresh AES-256 package key wrapped with recipient RSA-OAEP/SHA-256; sender RSA signature; pinned peer keys |
| Tamper detection | AES-GCM authentication, original hash and size comparison, handler signature, custody validation, alerts |
| Replay prevention | Durable package receipts and rejection of duplicate packages/evidence IDs |
| Audit and reports | Append-only SQLite events, signed JSON audit/report export, offline report checker |
| USB forensics | Source type, acquisition time, logical file preservation, optional device/USB reference |
| Documents/images/audio/video | File bytes preserved without type-specific transformation |
| Efficiency evaluation | Measured hash/signature/operation times, transfer sizes and times, CSV export |
| Traffic analysis | Explicit-interface PyShark capture and PCAP/PCAPNG analysis scripts |

RSA signing and node encryption use separate keys. Private handler and node keys are encrypted with the node's master key. Evidence metadata and audit text in SQLite are **not encrypted**. Filenames and files are never directly exposed as static URLs; downloads require authentication and successful verification and use attachment disposition.

Each evidence scope has an independent local custody chain. A receiving node preserves the sender's history and starts its own signed segment. Forwarding preserves earlier segments. Individual event signatures verify their contents, while the pinned immediate sender attests to the upstream history in its signed envelope; this does not implement a public certificate authority for every historic handler/node.

SQLite triggers prevent ordinary updates/deletions of audit events and original evidence metadata. Signatures detect changed events and missing links inside a chain. Detecting removal of an entire chain or its trailing records requires comparison with a previously exported signed checkpoint held elsewhere. An administrator who controls the application process and master key can forge new local signatures; this system does not claim protection from a fully compromised host or legal admissibility certification.

## Keys and backup

The default local master key is `keys/master.key` beneath the chosen data directory. It is convenient for a self-contained lab demonstration. An attacker who obtains that directory and key can decrypt the vault. For a managed installation, provide a Base64-encoded 32-byte `SECURECHAIN_MASTER_KEY` through a protected secret store and restrict filesystem access using the OS's permissions/ACLs. The application applies restrictive POSIX modes where supported; Windows ACLs must be managed by the deployment owner.

Back up the SQLite database, encrypted vault, encrypted private keys, and original master key **together** while the node is stopped, or use SQLite's backup API for a consistent live database copy. Keep signed audit exports separately for checkpoints. Losing the master key makes encrypted evidence unrecoverable. Startup refuses to silently replace missing keys for an existing node.

Evidence/package processing is bounded to 32 MB originals and an 80 MB HTTP request limit and is performed in memory. The application retains originals rather than providing deletion, key rotation, account recovery, or a distributed availability service.

## Wireshark and PyShark

Install Wireshark with TShark and the appropriate capture driver (Npcap on Windows), then:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-traffic.txt
tshark -D
```

Choose your actual network or Npcap loopback interface. Capture only the intended transfer:

```powershell
.\.venv\Scripts\python.exe tools/capture_traffic.py --interface YOUR_INTERFACE --seconds 30 --output transfer.pcapng
```

During the capture, send a previously unreceived evidence item. You can also save a capture using the Wireshark GUI with capture filter `tcp port 5000 or tcp port 5001`.

```powershell
.\.venv\Scripts\python.exe tools/analyze_traffic.py transfer.pcapng --output traffic-summary.json
```

The analysis returns real packet counts, bytes, duration, observed protocol distribution, throughput, retransmissions, and TLS packet count. Adjust `--filter` and `--display-filter` for other ports. TLS observations alone do not establish that certificates were validated or payloads were confidential. Report the loopback encrypted-envelope experiment separately from the real-device HTTPS experiment.

## Offline report verification

Download an evidence report and the reporting node identity. After independently checking that identity's fingerprint:

```powershell
.\.venv\Scripts\python.exe tools/verify_report.py SC-EVIDENCE-report.json --identity NODE-IDENTITY.json
```

This verifies the reporting-node signature, original handler signature, and custody links. A signed report can authentically state that a vault check **failed**; the tool displays the recorded result separately. Recompute SHA-256 on the actual evidence file when independently checking its content.

## Project layout

```text
SecureChain_Synopsis.docx       Provided requirements
run.py                        Single-node development launcher
launch_demo.py                 Two-node classroom launcher
Start-SecureChain.cmd          Windows shortcut for the demo
wsgi.py                       Deployment entry point
securechain/
  __init__.py                 HTTP API, authentication and policy
  crypto.py                   Hashing, RSA, AES-GCM and encrypted keys
  db.py                       SQLite schema and immutability triggers
  service.py                  Evidence lifecycle and secure transfer
  templates/index.html        Web application shell
  static/                     Dashboard CSS, JavaScript and icon
tools/
  capture_traffic.py          Explicit-interface traffic capture
  analyze_traffic.py          Capture measurements
  verify_report.py            Independent signed-report verification
```

## Technical references

Cryptographic choices follow the library's documented [RSA-PSS signing and RSA-OAEP encryption](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) and [AES-GCM authenticated encryption](https://cryptography.io/en/latest/hazmat/primitives/aead/). Session and request protections follow [Flask's security documentation](https://flask.palletsprojects.com/en/stable/web-security/). The capture tools use the documented [PyShark capture modes](https://pyshark-packet-analysis.readthedocs.io/en/latest/capture_usage/basic_usage/).
