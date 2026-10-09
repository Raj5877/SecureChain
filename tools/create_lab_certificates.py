"""Create an IP-bound HTTPS certificate pair for a private two-node lab."""
import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write_new(path, content, private=False):
    with path.open("xb") as stream:
        stream.write(content)
    if private:
        path.chmod(0o600)


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def generate(sender_ip, receiver_ip, output, days=30):
    addresses = [ipaddress.ip_address(value) for value in (sender_ip, receiver_ip)]
    if any(address.is_unspecified or address.is_multicast for address in addresses):
        raise ValueError("Use the actual device IPs, not 0.0.0.0, ::, or multicast addresses.")
    if not 1 <= days <= 365:
        raise ValueError("Certificate lifetime must be between 1 and 365 days.")
    # A fresh directory prevents replacement of any existing certificate or key.
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    output.chmod(0o700)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureChain Private Lab CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                         key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    write_new(output / "ca-key.pem", private_pem(ca_key), private=True)
    write_new(output / "ca-cert.pem", ca.public_bytes(serialization.Encoding.PEM))
    for role, address in zip(("sender", "receiver"), addresses):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"SecureChain {role}")]))
                .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(address)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                               key_encipherment=True, data_encipherment=False, key_agreement=False,
                               key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
        write_new(output / f"{role}-key.pem", private_pem(key), private=True)
        write_new(output / f"{role}-cert.pem", cert.public_bytes(serialization.Encoding.PEM))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender-ip", required=True, help="Actual sender device IP address")
    parser.add_argument("--receiver-ip", required=True, help="Actual receiver device IP address")
    parser.add_argument("--output", default="lab-certs", help="New output directory (must not already exist)")
    parser.add_argument("--days", type=int, default=30, help="Validity in days, from 1 to 365 (default: 30)")
    args = parser.parse_args()
    try:
        output = generate(args.sender_ip, args.receiver_ip, args.output, args.days)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(f"Created certificates in {output.resolve()}")
    print("Copy ca-cert.pem to both devices, and each device's own certificate/key to that device.")
    print("Keep ca-key.pem private on the generating computer. Do not copy it to the other node.")
    print("These certificates cover only the supplied IPs. New IPs require new certificates.")
    print("Set REQUESTS_CA_BUNDLE to ca-cert.pem, and trust that CA in the browsers you use.")


if __name__ == "__main__":
    main()
