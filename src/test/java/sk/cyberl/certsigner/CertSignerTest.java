package sk.cyberl.certsigner;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import sk.cyberl.certsigner.azure.KeyVaultSignerProvider;
import sk.cyberl.certsigner.config.CertSignerConfig;
import sk.cyberl.certsigner.logging.AttributeSource;
import sk.cyberl.certsigner.logging.CertificateAttributeLogger;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import javax.security.auth.x500.X500Principal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link CertSigner} certificate generation, signing, and provenance tracking.
 */
class CertSignerTest {

    /**
     * Initializes the Bouncy Castle security provider before all tests.
     */
    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Tests certificate generation and signing using direct Subject DN, public key file, and CLI extensions.
     */
    @Test
    void testDirectSubjectAndPublicKeyWithCliExtensions(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        Path pubKeyPath = tempDir.resolve("public.key");
        Files.write(pubKeyPath, keyPair.getPublic().getEncoded());

        // Create valid extension request attribute with KeyUsage and SAN
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        Extension kuExt = new Extension(Extension.keyUsage, true, new DEROctetString(keyUsage));

        GeneralNames san = new GeneralNames(new GeneralName(GeneralName.dNSName, "cli.example.com"));
        Extension sanExt = new Extension(Extension.subjectAlternativeName, false, new DEROctetString(san));

        Extensions extensions = new Extensions(new Extension[]{kuExt, sanExt});
        ASN1EncodableVector attrVec = new ASN1EncodableVector();
        attrVec.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        attrVec.add(new DERSet(extensions));
        DERSet attrSet = new DERSet(new DERSequence(attrVec));

        String base64Attrs = Base64.getEncoder().encodeToString(attrSet.getEncoded());

        CertSignerConfig config = new CertSignerConfig(
            tempDir.resolve("out.crt").toString(),
            null,
            "CN=direct-test,O=CyberL,C=SK",
            pubKeyPath.toString(),
            base64Attrs,
            365,
            "my-kv",
            "my-key",
            "v1",
            true
        );

        KeyVaultSignerProvider mockProvider = (kvName, kvKeyName, kvKeyVersion) -> {
            try {
                return new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        CertSigner signer = new CertSigner(config, mockProvider);
        byte[] certBytes = signer.signCert();

        assertNotNull(certBytes);
        String pem = new String(certBytes, StandardCharsets.UTF_8);
        assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        assertEquals("CN=direct-test,O=CyberL,C=SK", cert.getSubjectX500Principal().getName());

        // Verify extensions were included in the certificate
        assertNotNull(cert.getExtensionValue(Extension.keyUsage.getId()));
        assertNotNull(cert.getExtensionValue(Extension.subjectAlternativeName.getId()));

        // Verify attribute logger tracked sources
        CertificateAttributeLogger attrLogger = signer.getLastAttributeLogger();
        assertNotNull(attrLogger);
        assertEquals(AttributeSource.CLI, attrLogger.getExtensions().get(Extension.keyUsage).source());
        assertEquals(AttributeSource.CLI, attrLogger.getExtensions().get(Extension.subjectAlternativeName).source());
    }

    /**
     * Tests certificate generation and signing from a PKCS#10 CSR containing extension requests.
     */
    @Test
    void testCsrParsingAndCertConstructionWithExtensions(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        BasicConstraints bc = new BasicConstraints(false);
        Extension bcExt = new Extension(Extension.basicConstraints, true, new DEROctetString(bc));
        Extensions csrExtensions = new Extensions(new Extension[]{bcExt});

        org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder csrBuilder =
                new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                        new X500Principal("CN=csr-test,O=CyberL,C=SK"),
                        keyPair.getPublic()
                );
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, csrExtensions);

        org.bouncycastle.operator.ContentSigner csrSigner =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate());

        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);
        Path csrPath = tempDir.resolve("request.csr");
        Files.write(csrPath, csr.getEncoded());

        CertSignerConfig config = new CertSignerConfig(
            tempDir.resolve("out.crt").toString(),
            csrPath.toString(),
            null,
            null,
            null,
            90,
            "my-kv",
            "my-key",
            "v1",
            true
        );

        KeyVaultSignerProvider mockProvider = (kvName, kvKeyName, kvKeyVersion) -> {
            try {
                return new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        CertSigner certSigner = new CertSigner(config, mockProvider);
        byte[] certBytes = certSigner.signCert();

        assertNotNull(certBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        assertEquals("CN=csr-test,O=CyberL,C=SK", cert.getSubjectX500Principal().getName());
        assertNotNull(cert.getExtensionValue(Extension.basicConstraints.getId()));

        CertificateAttributeLogger attrLogger = certSigner.getLastAttributeLogger();
        assertNotNull(attrLogger);
        assertEquals(AttributeSource.CSR, attrLogger.getExtensions().get(Extension.basicConstraints).source());
    }

    /**
     * Tests certificate signing when merging CSR extensions with CLI attributes.
     */
    @Test
    void testMergeCsrAndCliExtensions(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        // CSR has BasicConstraints
        BasicConstraints bc = new BasicConstraints(false);
        Extension bcExt = new Extension(Extension.basicConstraints, true, new DEROctetString(bc));
        Extensions csrExtensions = new Extensions(new Extension[]{bcExt});

        org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder csrBuilder =
                new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                        new X500Principal("CN=merge-test,O=CyberL,C=SK"),
                        keyPair.getPublic()
                );
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, csrExtensions);

        org.bouncycastle.operator.ContentSigner csrSigner =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate());
        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);

        Path csrPath = tempDir.resolve("merge.csr");
        Files.write(csrPath, csr.getEncoded());

        // CLI has SAN
        GeneralNames san = new GeneralNames(new GeneralName(GeneralName.dNSName, "override.example.com"));
        Extension sanExt = new Extension(Extension.subjectAlternativeName, false, new DEROctetString(san));
        Extensions cliExtensions = new Extensions(new Extension[]{sanExt});

        ASN1EncodableVector attrVec = new ASN1EncodableVector();
        attrVec.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        attrVec.add(new DERSet(cliExtensions));
        DERSet cliAttrSet = new DERSet(new DERSequence(attrVec));

        String base64Attrs = Base64.getEncoder().encodeToString(cliAttrSet.getEncoded());

        CertSignerConfig config = new CertSignerConfig(
            tempDir.resolve("merged.crt").toString(),
            csrPath.toString(),
            null,
            null,
            base64Attrs,
            null, // Default validity
            "my-kv",
            "my-key",
            "v1",
            false
        );

        KeyVaultSignerProvider mockProvider = (kvName, kvKeyName, kvKeyVersion) -> {
            try {
                return new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        CertSigner certSigner = new CertSigner(config, mockProvider);
        byte[] certBytes = certSigner.signCert();

        assertNotNull(certBytes);
        CertificateAttributeLogger logger = certSigner.getLastAttributeLogger();
        assertNotNull(logger);

        // Basic Constraints came from CSR
        assertEquals(AttributeSource.CSR, logger.getExtensions().get(Extension.basicConstraints).source());
        // SAN came from CLI
        assertEquals(AttributeSource.CLI, logger.getExtensions().get(Extension.subjectAlternativeName).source());
    }

    /**
     * Tests certificate signing using an Elliptic Curve (ECDSA) key.
     */
    @Test
    void testEcKeyCertSigning(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecKeyPair = kpg.generateKeyPair();

        Path pubKeyPath = tempDir.resolve("ec-public.key");
        Files.write(pubKeyPath, ecKeyPair.getPublic().getEncoded());

        CertSignerConfig config = new CertSignerConfig(
            tempDir.resolve("out.pem").toString(),
            null,
            "CN=ec-test,O=CyberL,C=SK",
            pubKeyPath.toString(),
            null,
            180,
            "my-kv",
            "my-ec-key",
            "v1"
        );

        KeyVaultSignerProvider mockProvider = (kvName, kvKeyName, kvKeyVersion) -> {
            try {
                return new JcaContentSignerBuilder("SHA256withECDSA").build(ecKeyPair.getPrivate());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        CertSigner signer = new CertSigner(config, mockProvider);
        byte[] certBytes = signer.signCert();

        assertNotNull(certBytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        assertEquals("CN=ec-test,O=CyberL,C=SK", cert.getSubjectX500Principal().getName());
        assertDoesNotThrow(() -> cert.verify(ecKeyPair.getPublic()));
    }

    /**
     * Tests certificate output encoding in DER binary format when filename ends with {@code .der}.
     */
    @Test
    void testDerOutputFormat(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        Path pubKeyPath = tempDir.resolve("public.key");
        Files.write(pubKeyPath, keyPair.getPublic().getEncoded());

        CertSignerConfig config = new CertSignerConfig(
            tempDir.resolve("out.der").toString(),
            null,
            "CN=der-test,O=CyberL,C=SK",
            pubKeyPath.toString(),
            null,
            30,
            "my-kv",
            "my-key",
            "v1"
        );

        KeyVaultSignerProvider mockProvider = (kvName, kvKeyName, kvKeyVersion) -> {
            try {
                return new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };

        CertSigner signer = new CertSigner(config, mockProvider);
        byte[] certBytes = signer.signCert();

        assertNotNull(certBytes);
        X509CertificateHolder holder = new X509CertificateHolder(certBytes);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        assertEquals("CN=der-test,O=CyberL,C=SK", cert.getSubjectX500Principal().getName());
    }

    /**
     * Tests that an {@link IllegalArgumentException} is thrown when both CSR and Subject DN are missing.
     */
    @Test
    void testMissingBothCsrAndSubjectThrows() {
        CertSignerConfig config = new CertSignerConfig(
            "out.crt",
            null,
            null,
            null,
            null,
            null,
            "my-kv",
            "my-key",
            "v1"
        );

        CertSigner signer = new CertSigner(config);
        assertThrows(IllegalArgumentException.class, signer::signCert);
    }
}
