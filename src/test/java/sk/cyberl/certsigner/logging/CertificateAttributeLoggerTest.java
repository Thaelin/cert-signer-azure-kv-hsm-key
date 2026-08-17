package sk.cyberl.certsigner.logging;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class CertificateAttributeLoggerTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void testAttributeLoggerReportGeneration() throws Exception {
        CertificateAttributeLogger logger = new CertificateAttributeLogger();

        logger.addAttribute("Subject DN", "CN=test.example.com,O=Org,C=SK", AttributeSource.CSR);
        logger.addAttribute("Serial Number", "12345678 (0xBC614E)", AttributeSource.DEFAULT);
        logger.addAttribute("Issuer DN", "CN=test.example.com,O=Org,C=SK", AttributeSource.DEFAULT);
        logger.addValidity(new Date(1700000000000L), new Date(1731536000000L), 365, AttributeSource.CLI);
        logger.addAttribute("Signing Key", "Vault: 'my-vault', Key: 'my-key', Version: 'v1'", AttributeSource.CLI);
        logger.addAttribute("Signature Alg", "SHA256withRSA", AttributeSource.KEY_VAULT);

        BasicConstraints bc = new BasicConstraints(false);
        Extension bcExt = new Extension(Extension.basicConstraints, true, new DEROctetString(bc));
        logger.addExtension(bcExt, AttributeSource.CSR);

        KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        Extension kuExt = new Extension(Extension.keyUsage, true, new DEROctetString(ku));
        logger.addExtension(kuExt, AttributeSource.CLI);

        String report = logger.buildReport();

        assertNotNull(report);
        assertTrue(report.contains("CERTIFICATE ATTRIBUTES & PROVENANCE"));
        assertTrue(report.contains("[CSR]"));
        assertTrue(report.contains("[CLI]"));
        assertTrue(report.contains("[DEFAULT]"));
        assertTrue(report.contains("[KEY_VAULT]"));
        assertTrue(report.contains("Subject DN:"));
        assertTrue(report.contains("CN=test.example.com,O=Org,C=SK"));
        assertTrue(report.contains("Basic Constraints"));
        assertTrue(report.contains("Key Usage"));
        assertTrue(report.contains("CA: FALSE"));
        assertTrue(report.contains("Digital Signature, Key Encipherment"));

        // Verify SLF4J logging does not throw
        assertDoesNotThrow(logger::logReport);
    }

    @Test
    void testProcessAttributeSetWithExtensions() throws Exception {
        CertificateAttributeLogger logger = new CertificateAttributeLogger();

        BasicConstraints bc = new BasicConstraints(true);
        Extension bcExt = new Extension(Extension.basicConstraints, true, new DEROctetString(bc));

        Extensions extensions = new Extensions(new Extension[]{bcExt});

        ASN1EncodableVector attrVec = new ASN1EncodableVector();
        attrVec.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        attrVec.add(new DERSet(extensions));
        DERSet attrSet = new DERSet(new DERSequence(attrVec));

        logger.processAttributeSet(attrSet, AttributeSource.CSR);

        assertEquals(1, logger.getExtensions().size());
        assertTrue(logger.getExtensions().containsKey(Extension.basicConstraints));
        assertEquals(AttributeSource.CSR, logger.getExtensions().get(Extension.basicConstraints).source());
        assertTrue(logger.getExtensions().get(Extension.basicConstraints).formattedValue().contains("CA: TRUE"));
    }

    @Test
    void testPublicKeyFormattingRsaAndEc() throws Exception {
        // RSA
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaPair = rsaGen.generateKeyPair();
        SubjectPublicKeyInfo rsaSpki = SubjectPublicKeyInfo.getInstance(rsaPair.getPublic().getEncoded());

        String rsaDesc = CertificateAttributeLogger.formatPublicKeyInfo(rsaSpki);
        assertTrue(rsaDesc.contains("RSA 2048-bit"));
        assertTrue(rsaDesc.contains("65537"));

        // EC
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ecPair = ecGen.generateKeyPair();
        SubjectPublicKeyInfo ecSpki = SubjectPublicKeyInfo.getInstance(ecPair.getPublic().getEncoded());

        String ecDesc = CertificateAttributeLogger.formatPublicKeyInfo(ecSpki);
        assertTrue(ecDesc.contains("EC prime256v1 (256-bit)") || ecDesc.contains("256-bit"));
    }
}
