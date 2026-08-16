package sk.cyberl.certsigner.config;

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
