"""Self-signed certificate for a Vault Transit key, signed by Vault itself."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from asn1crypto import keys, pem, x509

from vault_transit_client import VaultKey, VaultTransitClient


def create_self_signed_certificate(
    vault: VaultTransitClient, key_name: str, key: VaultKey
) -> bytes:
    """Creates a self-signed X.509 certificate for a Vault key version, signed by Vault.

    Remarks:
        No GroupDocs API here; the result is the certificate that the PDF signature
        carries. A PDF reader checks the signature with the public key from this
        certificate, so it must be the Vault public key of the same version that signs.

        Uses asn1crypto to build the to-be-signed certificate around the Vault public
        key, hashes it locally (SHA-256) and gets the digest signed through
        transit/sign (prehashed, PKCS#1 v1.5, pinned key version). This is the first of
        two Vault sign requests per run; the second one signs the PDF digest. Subject
        and issuer are CN=Vault Transit Signer; key usage is digital signature; there
        is no private key anywhere outside Vault.

        It is valid from one day before now for one year. A PDF reader compares the
        signing time with the start date; a certificate made a second before signing
        was reported by Adobe Acrobat as "expired or not yet valid" on a machine two
        hours east of UTC.

        In production replace it with a CA-issued certificate for the same key: Transit
        can sign a CSR (transit/keys/{name}/csr), or the Vault PKI engine can act as a
        CA. Returns the certificate as DER bytes.
    """
    _, _, public_key_der = pem.unarmor(key.public_key_pem.encode("ascii"))
    name = x509.Name.build({"common_name": "Vault Transit Signer"})
    algorithm = x509.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})

    # Valid from yesterday: a PDF reader compares the signing time with this date, and a
    # clock or time-zone difference must not make a fresh certificate "not yet valid".
    now = datetime.now(timezone.utc).replace(microsecond=0)
    validity = x509.Validity({
        "not_before": x509.Time(name="utc_time", value=now - timedelta(days=1)),
        "not_after": x509.Time(name="utc_time", value=now + timedelta(days=365)),
    })

    tbs_certificate = x509.TbsCertificate({
        "version": "v3",
        "serial_number": secrets.randbits(127),
        "signature": algorithm,
        "issuer": name,
        "validity": validity,
        "subject": name,
        "subject_public_key_info": keys.PublicKeyInfo.load(public_key_der),
        "extensions": [
            {"extn_id": "basic_constraints", "critical": False,
             "extn_value": {"ca": False}},
            {"extn_id": "key_usage", "critical": False,
             "extn_value": {"digital_signature"}},
        ],
    })

    digest = hashlib.sha256(tbs_certificate.dump()).digest()
    signature = vault.sign_hash(key_name, key.version, digest, "sha2-256")

    certificate = x509.Certificate({
        "tbs_certificate": tbs_certificate,
        "signature_algorithm": algorithm,
        "signature_value": signature,
    })
    return certificate.dump()
