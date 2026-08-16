package sk.cyberl.certsigner;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import sk.cyberl.certsigner.config.CertSignerConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CertSignerTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testDirectSubjectAndPublicKeyParsing(@TempDir Path tempDir) throws Exception {
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

        CertSigner signer = new CertSigner(config);
        assertDoesNotThrow(signer::signCert);
    }

    @Test
    void testCsrParsingAndCertConstruction(@TempDir Path tempDir) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder csrBuilder =
                new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(
                        new org.bouncycastle.asn1.x500.X500Name("CN=csr-test,O=CyberL,C=SK"),
                        keyPair.getPublic()
                );

        org.bouncycastle.operator.ContentSigner signer =
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate());

        org.bouncycastle.pkcs.PKCS10CertificationRequest csr = csrBuilder.build(signer);
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

        CertSigner certSigner = new CertSigner(config);
        assertDoesNotThrow(certSigner::signCert);
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
