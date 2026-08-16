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
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import sk.cyberl.certsigner.config.CertSignerConfig;

public class CertSigner {

    private final CertSignerConfig config;

    public CertSigner(CertSignerConfig config) {
        this.config = config;
    }

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
            subjectDn = new X500Name(config.certSubjectDn());
            attributes = parseAttributes();
            subjectPublicKeyInfo = parsePublicKey();
        } else {
            throw new IllegalArgumentException("Either certCsrPath or certSubjectDn must be provided.");
        }

        X509v3CertificateBuilder certBuilder = createCertificateBuilder(subjectDn, subjectPublicKeyInfo, attributes);

        // TODO: Sign certificate using Azure Key Vault HSM key

        return null;
    }

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

    private CertificationRequestInfo parseCsr() {
        try {
            byte[] csrBytes = Files.readAllBytes(Path.of(config.certCsrPath()));
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);
            return csr.getCertificationRequestInfo();
        } catch (IOException e) {
            throw new RuntimeException("Failed to read CSR file: " + config.certCsrPath(), e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse CSR file: " + config.certCsrPath(), e);
        }
    }

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
}
