package sk.cyberl.certsigner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;

import sk.cyberl.certsigner.azure.DefaultKeyVaultSignerProvider;
import sk.cyberl.certsigner.azure.KeyVaultSignerProvider;
import sk.cyberl.certsigner.config.CertSignerConfig;
import sk.cyberl.certsigner.logging.AttributeSource;
import sk.cyberl.certsigner.logging.CertificateAttributeLogger;

/**
 * Certificate signer service that constructs X.509 v3 certificates and signs them
 * using cryptographic keys stored in Azure Key Vault (HSM).
 * <p>
 * Supports input from either a PKCS#10 Certificate Signing Request (CSR) or direct
 * Subject DN, Public Key, and optional ASN.1 certificate attributes/extensions.
 * Outputs certificates in either PEM or DER encoding and logs complete provenance.
 */
public class CertSigner {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertSigner.class);

    private final CertSignerConfig config;
    private final KeyVaultSignerProvider signerProvider;
    private CertificateAttributeLogger lastAttributeLogger;

    /**
     * Constructs a {@code CertSigner} with the given configuration and a {@link DefaultKeyVaultSignerProvider}.
     *
     * @param config The certificate signing configuration.
     * @throws NullPointerException if {@code config} is null.
     */
    public CertSigner(CertSignerConfig config) {
        this(config, new DefaultKeyVaultSignerProvider());
    }

    /**
     * Constructs a {@code CertSigner} with the given configuration and signer provider.
     *
     * @param config         The certificate signing configuration.
     * @param signerProvider The provider used to create the Key Vault {@link ContentSigner}.
     * @throws NullPointerException if {@code config} or {@code signerProvider} is null.
     */
    public CertSigner(CertSignerConfig config, KeyVaultSignerProvider signerProvider) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.signerProvider = Objects.requireNonNull(signerProvider, "signerProvider must not be null");
    }

    /**
     * Constructs and signs an X.509 certificate using Azure Key Vault HSM keys according to the configuration.
     *
     * @return Byte array containing the encoded certificate in PEM or DER format.
     * @throws IllegalArgumentException if neither CSR nor Subject DN is configured.
     * @throws RuntimeException         if reading CSR/keys, signing, or encoding the certificate fails.
     */
    public byte[] signCert() {
        LOGGER.info("Initializing certificate construction and signing workflow");

        CertificateAttributeLogger attrLogger = new CertificateAttributeLogger();
        this.lastAttributeLogger = attrLogger;

        X500Name subjectDn;
        SubjectPublicKeyInfo subjectPublicKeyInfo;

        boolean hasCsr = config.certCsrPath() != null && !config.certCsrPath().isBlank();
        boolean hasDirectSubject = config.certSubjectDn() != null && !config.certSubjectDn().isBlank();

        if (hasCsr) {
            LOGGER.info("Reading CSR from: {}", config.certCsrPath());
            CertificationRequestInfo csrInfo = parseCsr();
            subjectDn = csrInfo.getSubject();
            subjectPublicKeyInfo = csrInfo.getSubjectPublicKeyInfo();

            attrLogger.addAttribute("Subject DN", subjectDn.toString(), AttributeSource.CSR);
            attrLogger.addPublicKey(subjectPublicKeyInfo, AttributeSource.CSR);
            attrLogger.processAttributeSet(csrInfo.getAttributes(), AttributeSource.CSR);

            // If CLI also provided --cert-attributes, layer them on top
            if (config.certAttributes() != null && !config.certAttributes().isBlank()) {
                LOGGER.info("Layering additional CLI attributes from: {}", config.certAttributes());
                ASN1Set cliAttributes = parseAttributes();
                attrLogger.processAttributeSet(cliAttributes, AttributeSource.CLI);
            }
        } else if (hasDirectSubject) {
            LOGGER.info("Using direct Subject DN: {}", config.certSubjectDn());
            subjectDn = parseSubjectDn(config.certSubjectDn());
            subjectPublicKeyInfo = parsePublicKey();

            attrLogger.addAttribute("Subject DN", subjectDn.toString(), AttributeSource.CLI);
            attrLogger.addPublicKey(subjectPublicKeyInfo, AttributeSource.CLI);

            ASN1Set cliAttributes = parseAttributes();
            attrLogger.processAttributeSet(cliAttributes, AttributeSource.CLI);
        } else {
            throw new IllegalArgumentException("Either certCsrPath or certSubjectDn must be provided.");
        }

        // Validity and basic certificate fields
        X500Name issuer = subjectDn;
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        int validityDays = (config.validityDays() != null && config.validityDays() > 0) ? config.validityDays() : 365;
        Date notAfter = Date.from(now.plus(Duration.ofDays(validityDays)));

        AttributeSource validitySource = config.validityDaysExplicit() ? AttributeSource.CLI : AttributeSource.DEFAULT;

        attrLogger.addAttribute("Serial Number",
                serialNumber + " (0x" + serialNumber.toString(16).toUpperCase() + ")",
                AttributeSource.DEFAULT);
        attrLogger.addAttribute("Issuer DN", issuer.toString(), AttributeSource.DEFAULT);
        attrLogger.addValidity(notBefore, notAfter, validityDays, validitySource);

        attrLogger.addAttribute("Signing Key",
                String.format("Vault: '%s', Key: '%s', Version: '%s'",
                        config.kvName(),
                        config.kvKeyName(),
                        config.kvKeyVersion() != null && !config.kvKeyVersion().isBlank() ? config.kvKeyVersion() : "latest"
                ),
                AttributeSource.CLI);

        if (config.outputCertPath() != null) {
            attrLogger.addAttribute("Output Path", config.outputCertPath(), AttributeSource.CLI);
        }

        // Create certificate builder and populate extensions
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subjectDn,
                subjectPublicKeyInfo
        );

        // Add all tracked extensions into the certificate builder
        for (CertificateAttributeLogger.TrackedExtension ext : attrLogger.getExtensions().values()) {
            try {
                certBuilder.addExtension(ext.oid(), ext.critical(), getExtensionEncodedValue(ext));
            } catch (CertIOException e) {
                throw new RuntimeException("Failed to add extension to certificate builder: " + ext.oid().getId(), e);
            }
        }

        LOGGER.info("Requesting remote ContentSigner from Key Vault: {} / {}", config.kvName(), config.kvKeyName());
        ContentSigner contentSigner = signerProvider.createContentSigner(
                config.kvName(),
                config.kvKeyName(),
                config.kvKeyVersion()
        );

        String signatureAlgName = contentSigner.getAlgorithmIdentifier().getAlgorithm().getId();
        attrLogger.addAttribute("Signature Alg", signatureAlgName, AttributeSource.KEY_VAULT);

        // Log the complete certificate provenance and extension report
        attrLogger.logReport();

        LOGGER.info("Signing certificate via Azure Key Vault HSM...");
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        LOGGER.info("Certificate signed successfully");

        if (config.outputCertPath() != null && config.outputCertPath().toLowerCase().endsWith(".der")) {
            try {
                LOGGER.info("Encoding certificate to binary DER format");
                return certHolder.getEncoded();
            } catch (IOException e) {
                throw new RuntimeException("Failed to encode certificate to DER format", e);
            }
        }

        try (StringWriter sw = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            LOGGER.info("Encoding certificate to PEM format");
            pemWriter.writeObject(certHolder);
            pemWriter.flush();
            return sw.toString().getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode certificate to PEM format", e);
        }
    }

    /**
     * Resolves the DER-encoded ASN.1 value for a tracked extension.
     */
    private byte[] getExtensionEncodedValue(CertificateAttributeLogger.TrackedExtension ext) {
        // Find extension in parsed attributes / CSR to preserve exact byte structure
        if (config.certAttributes() != null && !config.certAttributes().isBlank()) {
            ASN1Set cliAttrs = parseAttributes();
            byte[] encoded = extractExtensionValue(cliAttrs, ext.oid());
            if (encoded != null) return encoded;
        }

        if (config.certCsrPath() != null && !config.certCsrPath().isBlank()) {
            CertificationRequestInfo csrInfo = parseCsr();
            byte[] encoded = extractExtensionValue(csrInfo.getAttributes(), ext.oid());
            if (encoded != null) return encoded;
        }

        return new byte[0];
    }

    /**
     * Helper to extract the encoded octets of a specific extension OID from an ASN.1 attribute set.
     */
    private byte[] extractExtensionValue(ASN1Set attributes, org.bouncycastle.asn1.ASN1ObjectIdentifier targetOid) {
        if (attributes == null) return null;

        for (org.bouncycastle.asn1.ASN1Encodable encodable : attributes.toArray()) {
            if (encodable instanceof Extension ext && ext.getExtnId().equals(targetOid)) {
                return ext.getExtnValue().getOctets();
            }

            try {
                org.bouncycastle.asn1.pkcs.Attribute attr = org.bouncycastle.asn1.pkcs.Attribute.getInstance(encodable);
                if (org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
                    ASN1Set attrValues = attr.getAttrValues();
                    if (attrValues != null && attrValues.size() > 0) {
                        org.bouncycastle.asn1.x509.Extensions extensions =
                                org.bouncycastle.asn1.x509.Extensions.getInstance(attrValues.getObjectAt(0));
                        Extension ext = extensions.getExtension(targetOid);
                        if (ext != null) {
                            return ext.getExtnValue().getOctets();
                        }
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse certificate attributes: " + config.certAttributes(), e);
            }
        }
        return null;
    }

    /**
     * Reads and parses the PKCS#10 Certificate Signing Request (CSR) from the configured file path.
     *
     * @return The parsed {@link CertificationRequestInfo}.
     * @throws RuntimeException if reading or parsing the CSR file fails.
     */
    private CertificationRequestInfo parseCsr() {
        try {
            byte[] csrBytes = Files.readAllBytes(Path.of(config.certCsrPath()));
            String content = new String(csrBytes, StandardCharsets.UTF_8);
            if (content.contains("-----BEGIN")) {
                try (PemReader reader = new PemReader(new StringReader(content))) {
                    PemObject pemObject = reader.readPemObject();
                    if (pemObject != null) {
                        csrBytes = pemObject.getContent();
                    }
                }
            }
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
            return csr.toASN1Structure().getCertificationRequestInfo();
        } catch (IOException e) {
            throw new RuntimeException("Failed to read CSR file: " + config.certCsrPath(), e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CSR file: " + config.certCsrPath(), e);
        }
    }

    /**
     * Parses certificate attributes from the configured DER file path or Base64-encoded string.
     *
     * @return The parsed {@link ASN1Set}, or {@code null} if no attributes are configured.
     * @throws RuntimeException if parsing the attributes fails.
     */
    private ASN1Set parseAttributes() {
        if (config.certAttributes() == null || config.certAttributes().isBlank()) {
            return null;
        }

        try {
            byte[] attrBytes;
            Path path = Path.of(config.certAttributes());
            if (Files.exists(path)) {
                attrBytes = Files.readAllBytes(path);
            } else {
                attrBytes = Base64.getDecoder().decode(config.certAttributes().trim());
            }

            try (ASN1InputStream asn1In = new ASN1InputStream(new ByteArrayInputStream(attrBytes))) {
                ASN1Primitive primitive = asn1In.readObject();
                if (primitive instanceof ASN1Set set) {
                    return set;
                } else if (primitive instanceof ASN1Sequence seq) {
                    return new DLSet(seq.toArray());
                } else if (primitive != null) {
                    return new DLSet(primitive);
                }
            }
            return null;
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse certificate attributes: " + config.certAttributes(), e);
        }
    }

    /**
     * Reads and parses the subject's public key from the configured file path.
     *
     * @return The parsed {@link SubjectPublicKeyInfo}, or {@code null} if no public key path is configured.
     * @throws RuntimeException if reading or parsing the public key file fails.
     */
    private SubjectPublicKeyInfo parsePublicKey() {
        if (config.certPublicKeyPath() == null || config.certPublicKeyPath().isBlank()) {
            return null;
        }

        try {
            byte[] keyBytes = Files.readAllBytes(Path.of(config.certPublicKeyPath()));
            String content = new String(keyBytes, StandardCharsets.UTF_8);
            if (content.contains("-----BEGIN")) {
                try (PemReader reader = new PemReader(new StringReader(content))) {
                    PemObject pemObject = reader.readPemObject();
                    if (pemObject != null) {
                        return SubjectPublicKeyInfo.getInstance(pemObject.getContent());
                    }
                }
            }
            return SubjectPublicKeyInfo.getInstance(keyBytes);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse public key file: " + config.certPublicKeyPath(), e);
        }
    }

    /**
     * Parses a Distinguished Name string into an {@link X500Name}.
     *
     * @param dn Distinguished Name string (e.g. "CN=example.com,O=Org,C=US").
     * @return The parsed {@link X500Name}.
     */
    private X500Name parseSubjectDn(String dn) {
        try {
            return X500Name.getInstance(new X500Principal(dn).getEncoded());
        } catch (Exception e) {
            return new X500Name(dn);
        }
    }

    /**
     * Returns the {@link CertificateAttributeLogger} from the most recent certificate signing operation.
     * Useful for testing and inspection.
     *
     * @return Last attribute logger instance.
     */
    public CertificateAttributeLogger getLastAttributeLogger() {
        return lastAttributeLogger;
    }
}
