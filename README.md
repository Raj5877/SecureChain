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

Open http://127.0.0.1:5002 and create the initial administrator. There are no default accounts on a clean node. New passwords require **12–256 characters**, including at least one uppercase letter, one lowercase letter, one number, and one special character that is not whitespace. The browser and server both enforce these rules when creating accounts; existing accounts can still sign in with their current passwords.

In **Node settings**, administrators can create investigator or viewer accounts. Investigators acquire, verify, and transfer evidence. Viewers inspect evidence, retrieve verified originals, and export reports. All authorized users share the node's evidence workspace; case-level isolation is outside this implementation.

## Manual feature walkthrough

1. Sign in to the sender and select your own file in **Register evidence**. The selection shows the filename and a separate **Size** label. Use **Remove selected file** to clear that selection before submitting, or select a replacement. Fill in the case reference, source, acquisition time, and optional USB identifier, then choose **Register & protect**. Selecting a file does not upload it; the successful registration message and evidence record confirm acceptance. Any binary format is accepted, including documents, images, audio, and video, up to **32 MB**. Larger originals are rejected in the browser before upload and are also rejected by the server.
2. Open **Evidence vault** and select the registered file to inspect its manifest, labeled file size, original hash, handler, acquisition source, and custody history.
3. Choose **Verify integrity**, leave the candidate field empty, and run verification. This decrypts and authenticates the stored original, recomputes SHA-256, verifies its RSA signature, and validates custody links.
4. Change a separate copy of that file. Upload it in the verification dialog. The expected result is a failed **SHA-256 match** with different registered and computed hashes. The original acquisition signature and custody checks can still pass because they describe the registered record. The registered original stays intact. The result explains the failed check, the custody entry identifies the external comparison, and security alerts update automatically after the operation.
5. Choose **Transfer**, select the receiving node, and choose **Send directly to peer URL** from the explicit delivery choices. The dialog shows the selected peer URL. If it is missing, an administrator can edit the trusted node's connection in **Node settings**, save its base URL, and retry. The receiver checks the sender signature, decrypts the package, validates the original hash, handler signature, and custody history, and returns a signed receipt. Only a validated receipt marks the sender transfer as delivered.
6. Alternatively, choose **Export encrypted .scpkg package** and upload it using **Receive package** on the receiver. A second upload of the same package is rejected as a replay. Offline export stays marked **Prepared** because no network receipt was received. A rejected package displays its verification analysis: completed checks, the failed stage, and later stages marked **Not checked**. Those later checks are not reported as successful when an earlier check prevents processing. The rejected file remains selected so you can inspect its name or clear it with **Remove selected file**; security alerts update without manually reloading the page.
7. Download a **Signed report** from the evidence record or a complete signed local audit from **Audit log**. Export CSV processing measurements from **Analytics**.
8. To remove a registered item from the active evidence list, archive it from its evidence record. Switch the vault to archived evidence to inspect it and restore it when needed. Archiving preserves the encrypted original, registration metadata, and custody history, and records the action. It does not erase the evidence or its audit trail.

Custody entries describe the operation and its outcome, including whether verification compared an external file or checked the stored original. Handler details and relevant check results appear with each event so a failed candidate comparison can be distinguished from a failed vault check.

Registration preserves the supplied file bytes. USB acquisition is a **logical file acquisition**: obtain the file using your forensic procedure, then register that file and the source identifier. SecureChain does not image physical disks, recover deleted files, or provide a hardware write blocker.

## Connect two real devices

SecureChain can run on two physical computers, or on a laptop and a VM. Run **one node on each device** using `run.py`; `launch_demo.py` is the same-computer shortcut. Each network node has its own accounts, database, encrypted vault and signing/encryption keys. Copy the source code to the second device, not the first node's `demo-data/`, `sender-data/`, `receiver-data/`, or private node keys.

### 1. Connect the devices and identify their IPs

| Setup | Network configuration |
| --- | --- |
| Laptop + lab PC | Use a LAN, Wi-Fi network, or hotspot that permits communication between the two devices. Being on the same Wi-Fi name does not guarantee this if client isolation is enabled. |
| Laptop + VirtualBox VM | Use a **Host-only** adapter for a private laptop-to-VM connection. If the VM also needs internet for installing packages, add a separate **NAT** adapter. |
| VM needs to communicate with a separate lab PC | Use **Bridged** networking so the VM has its own address on the physical network, where that network permits it. |

Default VirtualBox NAT alone needs port forwarding for connections into a guest; the host-only setup avoids that extra configuration. See [Oracle's networking mode comparison](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html).

On Windows, run `ipconfig` on both devices. On a Linux VM, run `ip -br address`. Use the address of the connected LAN or host-only adapter, not the VM's internet-only NAT address. Example addresses used below:

| Node | Example IP | HTTPS port | Data directory |
| --- | --- | --- | --- |
| Laptop / sender | `192.168.1.50` | `5000` | `sender-data` |
| Lab PC / receiver | `192.168.1.60` | `5001` | `receiver-data` |

Replace these examples with your actual IPs everywhere. For host-only networking the host and VM might instead have addresses such as `192.168.56.1` and `192.168.56.101`. `127.0.0.1` means the current device; it does not identify the other device. `0.0.0.0` is a listening address, not a peer URL. Different devices can also use the same port if desired.

Install Python 3.11+ and the core dependencies **on each device**, from its project folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

On Linux use `python3 -m venv .venv` and `.venv/bin/python -m pip install -r requirements.txt`; replace the Python command in the following examples with `.venv/bin/python`.

### 2. Create HTTPS certificates for the actual IPs

Direct network transfers require HTTPS. The included tool uses the installed `cryptography` package to create a private lab CA and one IP-bound certificate per node; OpenSSL is not required. Run it once on the laptop:

```powershell
.\.venv\Scripts\python.exe tools/create_lab_certificates.py --sender-ip 192.168.1.50 --receiver-ip 192.168.1.60
```

This creates a new `lab-certs/` folder with 30-day certificates. It refuses to overwrite an existing folder. If IPs change or certificates expire, generate a new folder with `--output lab-certs-new` and use/trust the replacement certificates.

On the receiver create a `lab-certs/` folder and copy only **`ca-cert.pem`, `receiver-cert.pem`, and `receiver-key.pem`** into it. The sender uses its own `sender-cert.pem` and `sender-key.pem`. Keep `ca-key.pem` on the generating computer; it is not needed to run either node. TLS certificates are separate from the SecureChain node identity files used for peer trust.

The browser must trust this private CA on whichever computer is used to open the site. For Windows Chrome/Edge, import the CA into the current user's Trusted Root Certification Authorities store:

```powershell
certutil -user -addstore Root .\lab-certs\ca-cert.pem
```

Import only the CA generated for your own lab. Other browsers/OSes may use a separate certificate store. A managed lab computer may require its administrator to approve CA trust. Access the site using the exact IP supplied to the generator; the certificates do not cover `localhost` or arbitrary names. Do not bypass browser certificate errors or disable Python certificate verification.

### 3. Start one node on each device

On the sender:

```powershell
$env:REQUESTS_CA_BUNDLE = (Resolve-Path .\lab-certs\ca-cert.pem).Path
.\.venv\Scripts\python.exe run.py --host 0.0.0.0 --port 5000 --name "Sender Lab" --data-dir sender-data --cert lab-certs/sender-cert.pem --key lab-certs/sender-key.pem
```

On the receiver:

```powershell
$env:REQUESTS_CA_BUNDLE = (Resolve-Path .\lab-certs\ca-cert.pem).Path
.\.venv\Scripts\python.exe run.py --host 0.0.0.0 --port 5001 --name "Receiver Lab" --data-dir receiver-data --cert lab-certs/receiver-cert.pem --key lab-certs/receiver-key.pem
```

On Linux set `export REQUESTS_CA_BUNDLE="$(pwd)/lab-certs/ca-cert.pem"` before running the node. The environment variable is needed on every sending node; set it again in a new terminal. [Requests documents custom CA bundles](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification).

Allow inbound TCP `5000` on the sender and `5001` on the receiver through their firewalls, scoped to the other device's IP. Use an authorized private lab network; ask the lab administrator if its firewall or network isolation blocks the connection. Do not disable the firewall or open router/internet port forwarding for this experiment.

From Windows, check the other node's port after starting it:

```powershell
# On the sender
Test-NetConnection 192.168.1.60 -Port 5001
# On the receiver
Test-NetConnection 192.168.1.50 -Port 5000
```

Open **`https://192.168.1.50:5000`** and **`https://192.168.1.60:5001`**. A fresh data directory asks you to create its administrator; it does not have the classroom demo login.

### 4. Trust the peers and test IP delivery

Download each public identity in **Node settings**. On the opposite node, choose **Trust a node**, upload that identity, and independently compare **both** SHA-256 key fingerprints through a trusted channel. The self-signature validates possession of the signing key; the out-of-band fingerprint comparison establishes who the node belongs to. Add the HTTPS base URL if direct delivery is required. An administrator can edit an existing trusted node's delivery URL and receiver token without replacing its pinned identity. Both nodes must trust each other for bidirectional exchange.

Set the sender's receiving peer URL to **`https://192.168.1.60:5001`**, and the receiver's peer URL back to **`https://192.168.1.50:5000`**. Then register a new file on the sender, open its record, choose **Transfer**, and select **Send directly to peer URL**. Success means the sender shows **Delivered** after verifying the receiver's signed receipt and the receiver shows the same evidence ID and SHA-256 in its own vault. For a reverse-direction test, register a different new file on the receiver; resending an already received evidence ID is deliberately rejected.

For Wireshark, capture the LAN adapter on physical devices, or the host-only/bridged adapter for VM communication. Use filter `tcp port 5000 or tcp port 5001`; Npcap loopback is for the same-computer localhost experiment. Install the optional traffic tools only on the device performing capture/analysis, not necessarily both nodes.

If connection fails: a port test failure indicates reachability/listener/firewall issues; a certificate error usually indicates an untrusted CA, wrong IP, expiry, or unset `REQUESTS_CA_BUNDLE`; a rejected package is diagnosed in the receiving node's audit log/alerts. Two-node source setup is included here, but actual lab-network connectivity depends on your chosen devices and network.

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
| Efficiency evaluation | Measured hash/signature/encryption/decryption/operation times, transfer sizes and times, CSV export |
| Traffic analysis | Explicit-interface TShark capture and PyShark PCAP/PCAPNG analysis scripts |

RSA signing and node encryption use separate keys. Private handler and node keys are encrypted with the node's master key. Evidence metadata and audit text in SQLite are **not encrypted**. Filenames and files are never directly exposed as static URLs; downloads require authentication and successful verification and use attachment disposition.

Each evidence scope has an independent local custody chain. A receiving node preserves the sender's history and starts its own signed segment. Forwarding preserves earlier segments. Individual event signatures verify their contents, while the pinned immediate sender attests to the upstream history in its signed envelope; this does not implement a public certificate authority for every historic handler/node.

SQLite triggers prevent ordinary updates/deletions of audit events and original evidence metadata. Signatures detect changed events and missing links inside a chain. Detecting removal of an entire chain or its trailing records requires comparison with a previously exported signed checkpoint held elsewhere. An administrator who controls the application process and master key can forge new local signatures; this system does not claim protection from a fully compromised host or legal admissibility certification.

## Processing measurements

Open **Analytics** for encryption/decryption averages and per-operation times in milliseconds, or choose **Export processing metrics** for CSV. **Transfer history** also shows outbound package encryption and inbound package decryption separately from processing/delivery time. Vault verification results show vault decryption time.

Registration measures AES-256-GCM vault encryption; vault verification measures vault decryption. Transfer preparation measures vault decryption and package encryption (AES-256-GCM plus RSA-OAEP key wrapping). Package reception measures package decryption (RSA-OAEP key unwrapping plus AES-256-GCM) and encryption of the received vault copy. External candidate comparison performs no decryption. Cryptographic timers exclude file I/O, JSON/Base64 conversion, signatures and network delivery; total processing/delivery timings cover the broader operation.

Existing databases add the timing columns automatically at startup without replacing evidence, keys, accounts, or custody records. Older rows have unavailable timings rather than fabricated zeroes. Averages skip unavailable values. Restart both nodes, register/verify evidence or make a new transfer, and refresh the page to collect new measurements. PCAP summaries describe network traffic and cannot derive these application cryptographic times.

## Keys and backup

The default local master key is `keys/master.key` beneath the chosen data directory. It is convenient for a self-contained lab demonstration. An attacker who obtains that directory and key can decrypt the vault. For a managed installation, provide a Base64-encoded 32-byte `SECURECHAIN_MASTER_KEY` through a protected secret store and restrict filesystem access using the OS's permissions/ACLs. The application applies restrictive POSIX modes where supported; Windows ACLs must be managed by the deployment owner.

Back up the SQLite database, encrypted vault, encrypted private keys, and original master key **together** while the node is stopped, or use SQLite's backup API for a consistent live database copy. Keep signed audit exports separately for checkpoints. Losing the master key makes encrypted evidence unrecoverable. Startup refuses to silently replace missing keys for an existing node.

Evidence/package processing is bounded to 32 MB originals and an 80 MB HTTP request limit and is performed in memory. File selection validates the size before submission. Archiving removes registered evidence from the active list while retaining its original and signed records; permanent deletion is not provided. The application does not provide key rotation, account recovery, or a distributed availability service.

## Wireshark and PyShark

Live capture uses the installed Wireshark/TShark runtime directly, including its automatic duration limit. Analysis also needs the Python PyShark package. Installing the Python package alone does not install TShark.

On Windows, download the installer from the [official Wireshark website](https://www.wireshark.org/download.html). Select the **TShark** component and install **Npcap** when prompted. Npcap is required for live capture; opening existing captures does not require it. See the [official Windows installation guide](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html).

Install the Python dependency from the project folder:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-traffic.txt
```

List the available interfaces using the default installation path:

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -D
```

If your installation uses another directory, substitute its actual path. If `tshark` is available on PATH, `tshark -D` also works. The `-D` option lists interfaces without starting a capture. See the [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html).

The scripts discover TShark on PATH and in standard Windows Wireshark directories. For a custom location, set the path for this terminal session:

```powershell
$env:TSHARK_PATH = "D:\Apps\Wireshark\tshark.exe"
```

Alternatively, pass `--tshark-path` to either script:

```powershell
.\.venv\Scripts\python.exe tools/capture_traffic.py --tshark-path "C:\Program Files\Wireshark\tshark.exe" --interface YOUR_INTERFACE --seconds 30 --output transfer-01.pcapng
.\.venv\Scripts\python.exe tools/analyze_traffic.py transfer-01.pcapng --tshark-path "C:\Program Files\Wireshark\tshark.exe" --output traffic-summary-01.json
```

Captures and named analysis summaries go into the project's **`captures/`** folder by default. The commands above create `captures/transfer-01.pcapng` and `captures/traffic-summary-01.json`. Omit `--output` when capturing to generate a unique UTC timestamped filename automatically. The folder is created as needed and excluded from Git. Explicit paths such as `captures/transfer-01.pcapng` or an absolute path are also supported; existing captures are never overwritten.

For the localhost demonstration, choose the Npcap loopback interface from the interface list. During capture, send an evidence item the receiver has not previously received. You can also save a capture using the Wireshark GUI with capture filter `tcp port 5000 or tcp port 5001`; save its file into `captures/` too. The tools report a missing-runtime error with installation and path instructions if TShark cannot be found; they do not install software automatically.

Interface numbers can change when virtual/VPN/network adapters are added. For the two-node localhost demo, use the stable `loopback` alias instead of a previously observed number:

```powershell
python tools/capture_traffic.py --interface loopback --seconds 60 --output transfer-03.pcapng
python tools/analyze_traffic.py transfer-03.pcapng --output traffic-summary-03.json
```

The capture command prints the resolved adapter name. During the capture choose **Send directly to peer URL** in SecureChain and wait for **Delivered**. For physical-device or VM transfers, select their actual LAN/host-only/bridged adapter instead. If a summary shows zero packets, check both the selected adapter and port filters; a completed application transfer does not mean the chosen adapter observed it. Saved empty captures cannot be repaired by rerunning analysis.

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
  create_lab_certificates.py  IP-bound HTTPS certificates for two-device labs
  tshark_support.py           TShark executable discovery and setup guidance
  verify_report.py            Independent signed-report verification
```

## Technical references

Cryptographic choices follow the library's documented [RSA-PSS signing and RSA-OAEP encryption](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/) and [AES-GCM authenticated encryption](https://cryptography.io/en/latest/hazmat/primitives/aead/). Session and request protections follow [Flask's security documentation](https://flask.palletsprojects.com/en/stable/web-security/). The capture tools use the documented [PyShark capture modes](https://pyshark-packet-analysis.readthedocs.io/en/latest/capture_usage/basic_usage/).
