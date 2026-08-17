package sk.cyberl.certsigner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.security.auth.x500.X500Principal;

import java.io.StringWriter;
import java.util.Objects;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;

import sk.cyberl.certsigner.azure.DefaultKeyVaultSignerProvider;
import sk.cyberl.certsigner.azure.KeyVaultSignerProvider;
import sk.cyberl.certsigner.config.CertSignerConfig;

/**
 * Certificate signer service that constructs X.509 v3 certificates and signs them
 * using cryptographic keys stored in Azure Key Vault (HSM).
 * <p>
 * Supports input from either a PKCS#10 Certificate Signing Request (CSR) or direct
 * Subject DN, Public Key, and optional ASN.1 certificate attributes/extensions.
 * Outputs certificates in either PEM or DER encoding.
 */
public class CertSigner {

    private final CertSignerConfig config;
    private final KeyVaultSignerProvider signerProvider;

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
        X500Name subjectDn;
        ASN1Set attributes;
        SubjectPublicKeyInfo subjectPublicKeyInfo;

        if (config.certCsrPath() != null && !config.certCsrPath().isBlank()) {
            CertificationRequestInfo csrInfo = parseCsr();
            subjectDn = csrInfo.getSubject();
            attributes = csrInfo.getAttributes();
            subjectPublicKeyInfo = csrInfo.getSubjectPublicKeyInfo();
        } else if (config.certSubjectDn() != null && !config.certSubjectDn().isBlank()) {
            subjectDn = parseSubjectDn(config.certSubjectDn());
            attributes = parseAttributes();
            subjectPublicKeyInfo = parsePublicKey();
        } else {
            throw new IllegalArgumentException("Either certCsrPath or certSubjectDn must be provided.");
        }

        X509v3CertificateBuilder certBuilder = createCertificateBuilder(subjectDn, subjectPublicKeyInfo, attributes);

        ContentSigner contentSigner = signerProvider.createContentSigner(
                config.kvName(),
                config.kvKeyName(),
                config.kvKeyVersion()
        );

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);

        if (config.outputCertPath() != null && config.outputCertPath().toLowerCase().endsWith(".der")) {
            try {
                return certHolder.getEncoded();
            } catch (IOException e) {
                throw new RuntimeException("Failed to encode certificate to DER format", e);
            }
        }

        try (StringWriter sw = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(certHolder);
            pemWriter.flush();
            return sw.toString().getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode certificate to PEM format", e);
        }
    }

    /**
     * Creates and initializes an {@link X509v3CertificateBuilder} with subject, validity period, public key, and extensions.
     *
     * @param subjectDn            The subject Distinguished Name.
     * @param subjectPublicKeyInfo The subject's public key info.
     * @param attributes           Optional ASN.1 set containing certificate attributes/extensions.
     * @return A configured {@link X509v3CertificateBuilder}.
     */
    private X509v3CertificateBuilder createCertificateBuilder(
            X500Name subjectDn,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            ASN1Set attributes) {
        X500Name issuer = subjectDn;
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        int validityDays = (config.validityDays() != null && config.validityDays() > 0) ? config.validityDays() : 365;
        Date notAfter = Date.from(now.plus(Duration.ofDays(validityDays)));

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                issuer,
                serialNumber,
                notBefore,
                notAfter,
                subjectDn,
                subjectPublicKeyInfo
        );

        addExtensions(certBuilder, attributes);

        return certBuilder;
    }

    /**
     * Extracts and adds extensions from the provided ASN.1 attributes set to the certificate builder.
     *
     * @param certBuilder The certificate builder to add extensions to.
     * @param attributes  ASN.1 set containing extensions or extension requests.
     * @throws RuntimeException if adding an extension to the certificate builder fails.
     */
    private void addExtensions(X509v3CertificateBuilder certBuilder, ASN1Set attributes) {
        if (attributes == null) {
            return;
        }

        for (ASN1Encodable encodable : attributes.toArray()) {
            if (encodable instanceof Extension extension) {
                try {
                    certBuilder.addExtension(extension);
                } catch (CertIOException e) {
                    throw new RuntimeException("Failed to add extension to certificate builder", e);
                }
                continue;
            }

            try {
                Attribute attr = Attribute.getInstance(encodable);
                if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
                    ASN1Set attrValues = attr.getAttrValues();
                    if (attrValues != null && attrValues.size() > 0) {
                        ASN1Encodable value = attrValues.getObjectAt(0);
                        Extensions extensions = Extensions.getInstance(value);
                        for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                            Extension ext = extensions.getExtension(oid);
                            certBuilder.addExtension(ext);
                        }
                    }
                }
            } catch (Exception ignored) {
                // Ignore attributes that cannot be parsed as extension requests
            }
        }
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
}
