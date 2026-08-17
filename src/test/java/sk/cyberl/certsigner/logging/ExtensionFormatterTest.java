package sk.cyberl.certsigner.logging;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class ExtensionFormatterTest {

    @Test
    void testBasicConstraintsFormatting() throws Exception {
        // CA: true with pathLenConstraint
        BasicConstraints caBc = new BasicConstraints(3);
        Extension caExt = new Extension(Extension.basicConstraints, true, new DEROctetString(caBc));
        String caFormatted = ExtensionFormatter.formatExtensionValue(caExt);
        assertTrue(caFormatted.contains("CA: TRUE"));
        assertTrue(caFormatted.contains("PathLenConstraint: 3"));

        // End-entity CA: false
        BasicConstraints eeBc = new BasicConstraints(false);
        Extension eeExt = new Extension(Extension.basicConstraints, false, new DEROctetString(eeBc));
        String eeFormatted = ExtensionFormatter.formatExtensionValue(eeExt);
        assertTrue(eeFormatted.contains("CA: FALSE"));
    }

    @Test
    void testKeyUsageFormatting() throws Exception {
        KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.cRLSign);
        Extension ext = new Extension(Extension.keyUsage, true, new DEROctetString(ku));
        String formatted = ExtensionFormatter.formatExtensionValue(ext);

        assertTrue(formatted.contains("Digital Signature"));
        assertTrue(formatted.contains("Key Encipherment"));
        assertTrue(formatted.contains("CRL Sign"));
        assertFalse(formatted.contains("Data Encipherment"));
    }

    @Test
    void testExtendedKeyUsageFormatting() throws Exception {
        ExtendedKeyUsage eku = new ExtendedKeyUsage(new KeyPurposeId[]{
                KeyPurposeId.id_kp_serverAuth,
                KeyPurposeId.id_kp_clientAuth,
                KeyPurposeId.id_kp_codeSigning
        });
        Extension ext = new Extension(Extension.extendedKeyUsage, false, new DEROctetString(eku));
        String formatted = ExtensionFormatter.formatExtensionValue(ext);

        assertTrue(formatted.contains("TLS Web Server Authentication"));
        assertTrue(formatted.contains("TLS Web Client Authentication"));
        assertTrue(formatted.contains("Code Signing"));
    }

    @Test
    void testSubjectAlternativeNameFormatting() throws Exception {
        GeneralNames san = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.dNSName, "example.com"),
                new GeneralName(GeneralName.dNSName, "www.example.com"),
                new GeneralName(GeneralName.rfc822Name, "admin@example.com"),
                new GeneralName(GeneralName.uniformResourceIdentifier, "https://example.com/api"),
                new GeneralName(GeneralName.iPAddress, "192.168.1.1")
        });
        Extension ext = new Extension(Extension.subjectAlternativeName, false, new DEROctetString(san));
        String formatted = ExtensionFormatter.formatExtensionValue(ext);

        assertTrue(formatted.contains("DNS:example.com"));
        assertTrue(formatted.contains("DNS:www.example.com"));
        assertTrue(formatted.contains("Email:admin@example.com"));
        assertTrue(formatted.contains("URI:https://example.com/api"));
        assertTrue(formatted.contains("IP:192.168.1.1"));
    }

    @Test
    void testSubjectKeyIdentifierAndAuthorityKeyIdentifierFormatting() throws Exception {
        byte[] keyIdBytes = new byte[]{(byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD};

        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(keyIdBytes);
        Extension skiExt = new Extension(Extension.subjectKeyIdentifier, false, new DEROctetString(ski));
        String skiFormatted = ExtensionFormatter.formatExtensionValue(skiExt);
        assertEquals("AA:BB:CC:DD", skiFormatted);

        GeneralNames issuerNames = new GeneralNames(new GeneralName(GeneralName.dNSName, "ca.example.com"));
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(keyIdBytes, issuerNames, BigInteger.valueOf(12345));
        Extension akiExt = new Extension(Extension.authorityKeyIdentifier, false, new DEROctetString(aki));
        String akiFormatted = ExtensionFormatter.formatExtensionValue(akiExt);

        assertTrue(akiFormatted.contains("KeyID: AA:BB:CC:DD"));
        assertTrue(akiFormatted.contains("CertIssuer: DNS:ca.example.com"));
        assertTrue(akiFormatted.contains("CertSerial: 3039"));
    }

    @Test
    void testCRLDistributionPointsFormatting() throws Exception {
        GeneralNames gns = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "http://crl.example.com/ca.crl"));
        DistributionPoint dp = new DistributionPoint(new DistributionPointName(DistributionPointName.FULL_NAME, gns), null, null);
        CRLDistPoint cdp = new CRLDistPoint(new DistributionPoint[]{dp});

        Extension ext = new Extension(Extension.cRLDistributionPoints, false, new DEROctetString(cdp));
        String formatted = ExtensionFormatter.formatExtensionValue(ext);
        assertTrue(formatted.contains("URI:http://crl.example.com/ca.crl"));
    }

    @Test
    void testAuthorityInformationAccessFormatting() throws Exception {
        AccessDescription ocsp = new AccessDescription(
                AccessDescription.id_ad_ocsp,
                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ocsp.example.com")
        );
        AccessDescription caIssuers = new AccessDescription(
                AccessDescription.id_ad_caIssuers,
                new GeneralName(GeneralName.uniformResourceIdentifier, "http://ca.example.com/ca.crt")
        );
        AuthorityInformationAccess aia = new AuthorityInformationAccess(new AccessDescription[]{ocsp, caIssuers});

        Extension ext = new Extension(Extension.authorityInfoAccess, false, new DEROctetString(aia));
        String formatted = ExtensionFormatter.formatExtensionValue(ext);

        assertTrue(formatted.contains("OCSP -> URI:http://ocsp.example.com"));
        assertTrue(formatted.contains("CA Issuers -> URI:http://ca.example.com/ca.crt"));
    }

    @Test
    void testCertificatePoliciesFormatting() throws Exception {
        PolicyQualifierInfo qualifierInfo = new PolicyQualifierInfo("http://example.com/cps");
        ASN1EncodableVector qualifiers = new ASN1EncodableVector();
        qualifiers.add(qualifierInfo);

        PolicyInformation policyInfo = new PolicyInformation(
                new ASN1ObjectIdentifier("2.16.840.1.12345.1"),
                new DERSequence(qualifiers)
        );
        CertificatePolicies cp = new CertificatePolicies(new PolicyInformation[]{policyInfo});

        Extension ext = new Extension(Extension.certificatePolicies, false, new DEROctetString(cp));
        String formatted = ExtensionFormatter.formatExtensionValue(ext);

        assertTrue(formatted.contains("Policy: 2.16.840.1.12345.1"));
        assertTrue(formatted.contains("CPS: http://example.com/cps"));
    }

    @Test
    void testNameConstraintsFormatting() throws Exception {
        GeneralSubtree[] permitted = new GeneralSubtree[]{
                new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".example.com"))
        };
        GeneralSubtree[] excluded = new GeneralSubtree[]{
                new GeneralSubtree(new GeneralName(GeneralName.dNSName, ".bad.example.com"))
        };
        NameConstraints nc = new NameConstraints(permitted, excluded);

        Extension ext = new Extension(Extension.nameConstraints, true, new DEROctetString(nc));
        String formatted = ExtensionFormatter.formatExtensionValue(ext);

        assertTrue(formatted.contains("Permitted: [DNS:.example.com]"));
        assertTrue(formatted.contains("Excluded: [DNS:.bad.example.com]"));
    }

    @Test
    void testFriendlyNameLookup() {
        assertEquals("Basic Constraints", ExtensionFormatter.getFriendlyName(Extension.basicConstraints));
        assertEquals("Key Usage", ExtensionFormatter.getFriendlyName(Extension.keyUsage));
        assertEquals("Subject Alternative Name", ExtensionFormatter.getFriendlyName(Extension.subjectAlternativeName));
        assertEquals("Extension Request", ExtensionFormatter.getFriendlyName(new ASN1ObjectIdentifier("1.2.840.113549.1.9.14")));

        ASN1ObjectIdentifier customOid = new ASN1ObjectIdentifier("1.2.3.4.5.6.7");
        assertEquals("1.2.3.4.5.6.7", ExtensionFormatter.getFriendlyName(customOid));
    }
}
