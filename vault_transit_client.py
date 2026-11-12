"""Minimal HTTP client for the HashiCorp Vault Transit secrets engine.

API: https://developer.hashicorp.com/vault/api-docs/secret/transit
"""
import base64
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VaultKey:
    """The latest version of a Transit key and its public key in PEM format."""

    version: int
    public_key_pem: str


class VaultError(Exception):
    """A Vault request failed; the message carries Vault's own error text."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class VaultTransitClient:
    """Sends Transit requests to one Vault with one token."""

    def __init__(self, vault_address: str, vault_token: str) -> None:
        """Creates a client that sends every request to one Vault with one token.

        Remarks:
            The token goes in the X-Vault-Token header of every request. With the local
            dev Vault from docker-compose.yml this is the root token dev-only-token; a
            real application uses a short-lived token from an auth method such as
            AppRole, limited by a policy to reading the key and signing with it. Use
            HTTPS outside a local test.
        """
        self._address = vault_address.rstrip("/")
        self._token = vault_token

    def read_key(self, key_name: str) -> Optional[VaultKey]:
        """Reads the latest version of a Transit key and its public key.

        Remarks:
            Calls GET /v1/transit/keys/{key_name}. Vault returns a map of all key
            versions with a public_key (PEM) for each, plus latest_version; this method
            returns the latest one. The private key is never part of the answer.

            Returns None when Vault answers 404: the key does not exist or Transit is
            not enabled. Any other error (for example 403 when the token may not read
            the key) raises VaultError with Vault's own message.

            The version matters: a certificate holds one public key, so the same version
            must be used for the certificate and for every sign request. After a key
            rotation the latest version changes and so does its public key.
        """
        try:
            data = self._request("GET", f"/v1/transit/keys/{key_name}")["data"]
        except VaultError as error:
            if error.status == 404:
                return None
            raise
        version = int(data["latest_version"])
        return VaultKey(version, data["keys"][str(version)]["public_key"])

    def enable_transit(self) -> None:
        """Enables the Transit secrets engine at transit/.

        Remarks:
            Calls POST /v1/sys/mounts/transit with type = transit. If Transit is already
            enabled, Vault answers 400 "path is already in use"; that answer is treated
            as success, any other error raises VaultError. This is an administrator
            action: it needs a token with rights on sys/mounts, which the root dev token
            has and a signing app should not have.
        """
        try:
            self._request("POST", "/v1/sys/mounts/transit", {"type": "transit"})
        except VaultError as error:
            if error.status != 400 or "path is already in use" not in str(error):
                raise

    def create_key(self, key_name: str, key_type: str) -> None:
        """Creates a Transit key whose private part is generated inside Vault.

        Remarks:
            Calls POST /v1/transit/keys/{key_name} with the key type, for example
            rsa-2048. The key is created with exportable = false (Vault's default), so
            no API returns the private key: transit/export/signing-key answers 400
            "private key material is not exportable". Creating a key that already
            exists returns the existing key unchanged. Like enable_transit, this is an
            administrator action.
        """
        self._request("POST", f"/v1/transit/keys/{key_name}", {"type": key_type})

    def sign_hash(
        self, key_name: str, key_version: int, digest: bytes, hash_algorithm: str
    ) -> bytes:
        """Signs an already computed digest with a Transit key; returns the raw signature.

        Remarks:
            Calls POST /v1/transit/sign/{key_name} with:
            - prehashed = true: the input is already a hash, so Vault signs it as it is.
              Without it Vault hashes the digest again and the PDF signature does not
              verify.
            - signature_algorithm = pkcs1v15: Vault's default for RSA keys is PSS, but
              the PDF signature here is sha256WithRSAEncryption (PKCS#1 v1.5).
            - key_version: pins the signature to the key version in the certificate.
            - hash_algorithm: Vault name such as sha2-256. Vault checks the digest
              length against it; a mismatch fails with 500 "crypto/rsa: input must be
              hashed message".

            Vault answers vault:v{version}:{base64 signature}; the method returns the
            decoded signature bytes (256 bytes for RSA-2048). A token without update on
            transit/sign/{key_name} gets 403, which raises VaultError.
        """
        request = {
            "input": base64.b64encode(digest).decode("ascii"),
            "key_version": key_version,
            "hash_algorithm": hash_algorithm,
            "prehashed": True,
            "signature_algorithm": "pkcs1v15",
        }
        data = self._request("POST", f"/v1/transit/sign/{key_name}", request)["data"]
        # Vault returns "vault:v<version>:<base64 signature>".
        return base64.b64decode(data["signature"].rsplit(":", 1)[1])

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        """Sends one request and raises VaultError with Vault's own error text."""
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self._address + path, data, method=method)
        request.add_header("X-Vault-Token", self._token)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                text = response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            raise VaultError(
                f"Vault {method} {path} failed with {error.code}: "
                f"{_error_text(error.read())}",
                error.code,
            ) from None
        except urllib.error.URLError as error:
            raise VaultError(
                f"Cannot reach Vault at {self._address}: {error.reason}"
            ) from None
        return json.loads(text) if text else {}


def _error_text(body: bytes) -> str:
    """Joins Vault's error list into one line; keeps the raw body if it is not JSON."""
    text = body.decode("utf-8", "replace")
    try:
        errors = json.loads(text)["errors"]
    except (ValueError, KeyError, TypeError):
        return text.strip()
    # Vault's messages contain line breaks and tabs: keep them on one line.
    return "; ".join(re.sub(r"\s+", " ", str(e)).strip() for e in errors)
