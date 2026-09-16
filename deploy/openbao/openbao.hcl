# The bundled OpenBao (ADR-0008): file storage on its own volume and the
# static seal, whose key tc init writes to the seal volume and the
# container's start command hands over in BAO_SEAL_KEY (see compose.yaml).
#
# A static seal key on the same host as OpenBao's data is a convenience,
# not a security boundary: anyone who can read both volumes can read every
# Secret. For production, move the seal to a KMS or HSM, see
# https://openbao.org/docs/concepts/seal/ and the seal migration procedure
# there.
ui = false

listener "tcp" {
  # Only TrustedCourier reaches this listener, over the compose network. To
  # put TLS on it, add tls_cert_file and tls_key_file here and BAO_CACERT
  # to the Backend Plugin's env in trustedcourier.yaml.
  address     = "0.0.0.0:8200"
  tls_disable = true
}

storage "file" {
  path = "/openbao/file"
}

seal "static" {
  current_key_id = "trustedcourier-1"
  current_key    = "env://BAO_SEAL_KEY"
}

# The Backend Plugin's token lives this long; it does not renew itself.
max_lease_ttl = "8760h"
