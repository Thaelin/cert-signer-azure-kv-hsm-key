package sk.cyberl.certsigner;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import sk.cyberl.certsigner.azure.KeyVaultSignerProvider;
import sk.cyberl.certsigner.config.CertSignerConfig;

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

class CertSignerTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testDirectSubjectAndPublicKeyParsingAndSigning(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        Path pubKeyPath = tempDir.resolve("public.key");
        Files.write(pubKeyPath, keyPair.getPublic().getEncoded());

        DERSet attrSet = new DERSet(new DERSequence(new ASN1EncodableVector() {{
            add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            add(new DERSet(new DERUTF8String("test-extension")));
        }}));
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
        String pem = new String(certBytes, StandardCharsets.UTF_8);
        assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(pem.contains("-----END CERTIFICATE-----"));

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        assertEquals("CN=direct-test,O=CyberL,C=SK", cert.getSubjectX500Principal().getName());
        assertDoesNotThrow(() -> cert.verify(keyPair.getPublic()));
    }

    @Test
    void testCsrParsingAndCertConstruction(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder csrBuilder =
                new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                        new X500Principal("CN=csr-test,O=CyberL,C=SK"),
                        keyPair.getPublic()
                );

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
            "v1"
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
        assertDoesNotThrow(() -> cert.verify(keyPair.getPublic()));
    }

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
