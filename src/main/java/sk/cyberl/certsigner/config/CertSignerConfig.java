package sk.cyberl.certsigner.config;

/**
 * Configuration parameters for certificate generation and signing with Azure Key Vault HSM keys.
 *
 * @param outputCertPath    Path where the generated certificate should be written.
 * @param certCsrPath       Path to the PEM or DER encoded Certificate Signing Request (CSR) file.
 * @param certSubjectDn     Subject Distinguished Name (e.g. "CN=example.com,O=Org,C=US") when not using a CSR.
 * @param certPublicKeyPath Path to the subject's public key file when not using a CSR.
 * @param certAttributes    Path to an ASN.1 DER file or Base64-encoded ASN.1 attributes string.
 * @param validityDays      Validity period of the generated certificate in days.
 * @param kvName            Azure Key Vault name or full vault URL.
 * @param kvKeyName         Key name in Azure Key Vault.
 * @param kvKeyVersion      Key version in Azure Key Vault.
 */
public record CertSignerConfig(
    String outputCertPath,
    String certCsrPath,
    String certSubjectDn,
    String certPublicKeyPath,
    String certAttributes,
    Integer validityDays,
    String kvName,
    String kvKeyName,
    String kvKeyVersion
) { }
