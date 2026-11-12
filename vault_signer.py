"""External signer for GroupDocs.Signature that signs with a key kept in Vault Transit."""
from groupdocs.signature.domain import HashAlgorithm

from vault_transit_client import VaultTransitClient

# GroupDocs.Signature hash algorithm -> Vault Transit hash_algorithm name
_VAULT_HASH_ALGORITHMS = {
    HashAlgorithm.SHA1: "sha1",
    HashAlgorithm.SHA256: "sha2-256",
    HashAlgorithm.SHA384: "sha2-384",
    HashAlgorithm.SHA512: "sha2-512",
}


class VaultSigner:
    """Signs the digest that GroupDocs.Signature computed, with a key in Vault Transit."""

    def __init__(self, vault: VaultTransitClient, key_name: str, key_version: int) -> None:
        """Creates a signer bound to one Vault Transit key version.

        Remarks:
            Pass the key version that the certificate was made for. A certificate holds
            one public key, so if Vault signed with another version (for example the
            latest one after a key rotation), the PDF would be written without any error
            but would not verify.
        """
        self._vault = vault
        self._key_name = key_name
        self._key_version = key_version

    def custom_sign_hash(
        self, signable_hash: bytes, hash_algorithm: HashAlgorithm, signature_context
    ) -> bytes:
        """Gets the digest of the PDF signed by Vault and returns the raw signature bytes.

        Remarks:
            The GroupDocs.Signature hook for external signing (ICustomSignHash). Set
            through DigitalSignOptions.custom_sign_hash, which accepts an object with
            this method or a plain function with the same arguments (from 26.10).
            GroupDocs.Signature calls it once per PDF signature. signable_hash is
            already a digest of the PDF's signed bytes (32 bytes for SHA-256), and it is
            exactly the value the signature must cover, so it goes to Vault with
            prehashed = true and is never hashed again.

            hash_algorithm is the algorithm GroupDocs.Signature really used, so it maps
            one to one to Vault names: SHA1 to sha1, SHA256 to sha2-256, SHA384 to
            sha2-384, SHA512 to sha2-512. Any other value raises ValueError. SHA-1 works
            but is a legacy algorithm that validators may reject. signature_context is
            not used.

            If Vault refuses (for example 403 for a token without sign rights), the
            exception stops Signature.sign and comes out of it unchanged.
        """
        vault_hash_algorithm = _VAULT_HASH_ALGORITHMS.get(hash_algorithm)
        if vault_hash_algorithm is None:
            raise ValueError(f"Hash algorithm {hash_algorithm!r} is not supported.")
        return self._vault.sign_hash(
            self._key_name, self._key_version, bytes(signable_hash), vault_hash_algorithm
        )
