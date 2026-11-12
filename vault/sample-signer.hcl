# Least-privilege policy for the sample: read the signing key and sign with it.
# Nothing else.
# Upload: vault policy write sample-signer sample-signer.hcl
path "transit/keys/pdf-signing-key" {
  capabilities = ["read"]
}

path "transit/sign/pdf-signing-key" {
  capabilities = ["update"]
}
