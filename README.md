# cert-signer-azure-kv-hsm-key
Program that can be used to create digital certificate based on CSR (or without) using Azure Key Vault premium HSM keys (non-exportable). Standard OpenSSL APIs expect signing key to be present in the environment but in case of HSM keys they are by nature non-exportable so dedicated cloud vendors key signing API needs to be used.
