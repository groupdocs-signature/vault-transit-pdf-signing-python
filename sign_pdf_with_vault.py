"""Sign a PDF with GroupDocs.Signature while the private key stays in HashiCorp Vault.

GroupDocs.Signature computes the PDF digest and calls VaultSigner, which gets the digest
signed by the Vault Transit engine. The key is created inside Vault and never leaves it.
"""
import io
import os
import sys
from datetime import datetime
from pathlib import Path

import groupdocs.signature as gs
from groupdocs.signature.domain import (
    DigitalSignature, HashAlgorithm, HorizontalAlignment, Padding, VerticalAlignment)
from groupdocs.signature.options import DigitalSignOptions, DigitalVerifyOptions

from certificate_helper import create_self_signed_certificate
from vault_signer import VaultSigner
from vault_transit_client import VaultKey, VaultTransitClient

# Defaults for the local Vault from docker-compose.yml (dev mode only). Set VAULT_ADDR
# and VAULT_TOKEN to use another Vault or a less powerful token.
DEFAULT_VAULT_ADDRESS = "http://localhost:8200"
DEFAULT_VAULT_TOKEN = "dev-only-token"
KEY_NAME = "pdf-signing-key"

HERE = Path(__file__).resolve().parent
INPUT_PDF = HERE / "Resources" / "document.pdf"
OUTPUT_PDF = HERE / "Result" / "signed_document.pdf"


def main() -> int:
    set_license("REPLACE_WITH_YOUR_LICENSE_PATH")

    if not INPUT_PDF.is_file():
        print(f"ERROR: input PDF not found: {INPUT_PDF}")
        return 1

    vault_address = os.environ.get("VAULT_ADDR") or DEFAULT_VAULT_ADDRESS
    vault_token = os.environ.get("VAULT_TOKEN") or DEFAULT_VAULT_TOKEN

    try:
        print(f"Vault: {vault_address}")
        vault = VaultTransitClient(vault_address, vault_token)

        key = get_or_create_key(vault)
        print(f"Signing key: '{KEY_NAME}', version {key.version}")

        print("Creating a self-signed certificate for the Vault key (signed by Vault)...")
        certificate = create_self_signed_certificate(vault, KEY_NAME, key)

        print(f"Signing '{INPUT_PDF.name}' "
              "(the digest goes to Vault, the key stays there)...")
        sign_pdf(INPUT_PDF, OUTPUT_PDF, certificate,
                 VaultSigner(vault, KEY_NAME, key.version))
        print(f"Signed PDF: {OUTPUT_PDF}")

        is_valid = verify_pdf(OUTPUT_PDF, certificate)
        print(f"Signature valid: {is_valid}")
        return 0 if is_valid else 1
    except Exception as error:  # pylint: disable=broad-except
        # GroupDocs errors carry a .NET stack trace after the first line.
        print(f"ERROR: {str(error).splitlines()[0] if str(error) else repr(error)}")
        return 1


def set_license(license_path: str) -> None:
    if os.path.isfile(license_path):
        gs.License().set_license(license_path)
    else:
        print("No licence file found: running in evaluation mode "
              "(documents of up to 2 pages).")


def get_or_create_key(vault: VaultTransitClient) -> VaultKey:
    """Reads the signing key from Vault Transit and creates it first if it does not exist.

    Remarks:
        No GroupDocs API here; this prepares the key that the PDF signature will use. It
        calls VaultTransitClient.read_key (GET /v1/transit/keys/{name}). If Vault answers
        404 (no such key, or Transit not enabled), it enables Transit, creates an
        RSA-2048 key and reads it again. The result is the key's latest version and its
        public key in PEM.

        Reading first matters for least privilege: a token that may only read the key
        and sign with it (policy vault/sample-signer.hcl) skips the setup and never
        needs admin rights. Without such rights the setup calls fail with 403, which is
        the expected answer.

        In production an administrator creates the key once; the sample does it here so
        that the local demo works out of the box.
    """
    key = vault.read_key(KEY_NAME)
    if key is not None:
        return key

    print(f"Key '{KEY_NAME}' not found: enabling Transit and creating "
          "an RSA-2048 key (one-time setup)...")
    vault.enable_transit()
    vault.create_key(KEY_NAME, "rsa-2048")
    key = vault.read_key(KEY_NAME)
    if key is None:
        raise RuntimeError(f"Key '{KEY_NAME}' was not found after it was created.")
    return key


def sign_pdf(input_pdf: Path, output_pdf: Path, certificate: bytes,
             signer: VaultSigner) -> None:
    """Signs a PDF with a digital signature whose private key stays in HashiCorp Vault.

    Remarks:
        Uses Signature.sign with DigitalSignOptions. GroupDocs.Signature prepares the
        PDF, computes the SHA-256 digest of the signed byte range and calls
        DigitalSignOptions.custom_sign_hash, here a VaultSigner that gets the digest
        signed by Vault. GroupDocs then embeds the signature and the certificate.
        Input: a PDF path and the certificate as DER bytes; output: the signed PDF at
        output_pdf.

        Notable options:
        - signature = DigitalSignature(certificate=...): the certificate holds only the
          public key. DigitalSignOptions(path or stream) expects a certificate with a
          private key and fails with "Specified certificate doesn't contain private
          key". The Python API has no X.509 type of its own, so the certificate object
          is taken from DigitalVerifyOptions, which loads a public-only certificate.
        - sign_time = datetime.now().astimezone(): a time with a time zone is stored in
          the PDF with it (for example +02'00'). The default UTC time and a naive local
          time are stored without one, and PDF readers then read them as their own
          local time.
        - hash_algorithm = SHA256: also the default for PDF.
        - visible with bottom/right alignment and a margin: a 300 x 80 pt box in the
          bottom-right corner with signer, date, reason, location and contact.

        Edge cases: if signing fails (for example Vault refuses with 403), the partial
        output file is deleted, because a failed sign can leave a half-written PDF. The
        signer's exception comes out of Signature.sign unchanged. Without a licence,
        evaluation mode refuses documents of more than 2 pages.

        Use this pattern when the signing key must stay in a key manager (Vault, an
        HSM, a cloud KMS) and the application may only ask for signatures.
    """
    # The certificate holds only the public key, so it is passed as an object. Python
    # has no X.509 type here: DigitalVerifyOptions loads a public-only certificate and
    # exposes the object that DigitalSignature takes.
    certificate_object = DigitalVerifyOptions(
        certificate_stream=io.BytesIO(certificate)).certificate
    digital_signature = DigitalSignature(certificate=certificate_object)
    # A time with a time zone is stored in the PDF with it (the default UTC time is not)
    digital_signature.sign_time = datetime.now().astimezone()

    options = DigitalSignOptions()
    options.signature = digital_signature
    options.custom_sign_hash = signer
    options.hash_algorithm = HashAlgorithm.SHA256
    # Visible box in the bottom-right corner of the page, wide enough for the Reason line
    options.visible = True
    options.vertical_alignment = VerticalAlignment.BOTTOM
    options.horizontal_alignment = HorizontalAlignment.RIGHT
    margin = Padding()
    margin.bottom = 60
    margin.right = 50
    options.margin = margin
    options.width = 300
    options.height = 80
    options.reason = "Document signed with HashiCorp Vault Transit"
    options.contact = "vault-signer@example.com"
    options.location = "HashiCorp Vault"

    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    try:
        with gs.Signature(str(input_pdf)) as signature:
            signature.sign(str(output_pdf), options)
    except Exception:
        # A failed sign can leave a half-written PDF behind.
        if output_pdf.exists():
            output_pdf.unlink()
        raise


def verify_pdf(signed_pdf: Path, certificate: bytes) -> bool:
    """Verifies the signed PDF against the certificate that was used to sign it.

    Remarks:
        Uses Signature.verify with DigitalVerifyOptions built from the certificate (DER
        bytes, the public part only). Input: the signed PDF path and the certificate;
        output: VerificationResult.is_valid.

        The check is cryptographic: it is False when the document was changed after
        signing or when the signature was made with another key, for example a
        different Vault key version than the one in the certificate. Pass the
        certificate: verifying without one does not tie the result to the expected
        signer.

        A self-signed certificate is enough for this check. PDF readers such as Adobe
        Acrobat additionally look for a trusted issuer and report the signer's identity
        as unknown.
    """
    options = DigitalVerifyOptions(certificate_stream=io.BytesIO(certificate))
    with gs.Signature(str(signed_pdf)) as signature:
        return signature.verify(options).is_valid


if __name__ == "__main__":
    sys.exit(main())
