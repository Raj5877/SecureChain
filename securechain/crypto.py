"""Cryptographic primitives. Evidence and keys use different AAD namespaces."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def public_pem(key) -> str:
    public = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    return public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def load_public(pem: str):
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError("An RSA public key of at least 3072 bits is required.")
    return key


def fingerprint(pem: str) -> str:
    key = load_public(pem)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return digest(der)


def sign(key, data: bytes) -> str:
    return b64(key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))


def verify(pem: str, data: bytes, signature: str) -> bool:
    try:
        load_public(pem).verify(unb64(signature), data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError, TypeError, UnicodeError):
        return False


def encrypt(key: bytes, data: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, aad)


def decrypt(key: bytes, data: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(data[:12], data[12:], aad)


def private_bytes(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_private(data: bytes):
    return serialization.load_pem_private_key(data, password=None)


def write_secret(path: Path, data: bytes):
    # Exclusive creation prevents accidental replacement of existing secrets.
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


class Keyring:
    def __init__(self, directory: Path, master_key: str | None = None):
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        path = directory / "master.key"
        if master_key:
            self.master = unb64(master_key)
        elif path.exists():
            self.master = path.read_bytes()
        else:
            if any(directory.glob("*.enc")) or (directory.parent / "securechain.sqlite3").exists():
                raise RuntimeError("The master key is missing. Restore it from backup; existing evidence cannot use a new key.")
            self.master = AESGCM.generate_key(bit_length=256)
            write_secret(path, self.master)
        if len(self.master) != 32:
            raise ValueError("SECURECHAIN_MASTER_KEY must encode exactly 32 bytes.")
        self.signing = self._node_key("node-signing")
        self.encryption = self._node_key("node-encryption")
        self.node_id = "NODE-" + fingerprint(public_pem(self.signing))[:16].upper()

    def _node_key(self, name):
        path = self.directory / f"{name}.enc"
        if not path.exists():
            if (self.directory.parent / "securechain.sqlite3").exists():
                raise RuntimeError(f"The {name} key is missing. Restore it from backup rather than replacing this node's identity.")
            key = new_key()
            write_secret(path, encrypt(self.master, private_bytes(key), name.encode()))
        return load_private(decrypt(self.master, path.read_bytes(), name.encode()))

    def protect_handler(self, key, username):
        return encrypt(self.master, private_bytes(key), f"handler:{username}".encode())

    def handler_key(self, data, username):
        return load_private(decrypt(self.master, data, f"handler:{username}".encode()))

    def descriptor(self, name):
        body = {"version": 1, "node_id": self.node_id, "name": name,
                "signing_key": public_pem(self.signing), "encryption_key": public_pem(self.encryption)}
        return {**body, "signature": sign(self.signing, canonical(body))}


def seal(payload: dict, recipient_pem: str, recipient_id: str, sender_id: str, signing_key) -> dict:
    key = AESGCM.generate_key(bit_length=256)
    header = {"format": "securechain-envelope", "version": 1, "recipient": recipient_id, "sender": sender_id}
    body = {**header, "wrapped_key": b64(load_public(recipient_pem).encrypt(key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))),
        "ciphertext": b64(encrypt(key, canonical(payload), canonical(header)))}
    return {**body, "signature": sign(signing_key, canonical(body))}


def open_envelope(envelope: dict, recipient_id: str, private_key, sender_pem: str) -> dict:
    expected = {"format", "version", "recipient", "sender", "wrapped_key", "ciphertext", "signature"}
    if not isinstance(envelope, dict) or set(envelope) != expected:
        raise ValueError("Invalid transfer envelope.")
    if envelope["format"] != "securechain-envelope" or envelope["version"] != 1 or envelope["recipient"] != recipient_id:
        raise ValueError("This package is not addressed to this node.")
    body = {k: v for k, v in envelope.items() if k != "signature"}
    if not verify(sender_pem, canonical(body), envelope["signature"]):
        raise ValueError("Sender signature is invalid. Package rejected.")
    key = private_key.decrypt(unb64(envelope["wrapped_key"]), padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    header = {k: envelope[k] for k in ("format", "version", "recipient", "sender")}
    return json.loads(decrypt(key, unb64(envelope["ciphertext"]), canonical(header)))
