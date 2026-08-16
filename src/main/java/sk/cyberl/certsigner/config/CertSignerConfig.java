package sk.cyberl.certsigner.config;

public record CertSignerConfig(
    String signingCertPath,
    String certCsrPath,
    String kvName,
    String kvKeyName,
    String kvKeyVersion
)
{ }
