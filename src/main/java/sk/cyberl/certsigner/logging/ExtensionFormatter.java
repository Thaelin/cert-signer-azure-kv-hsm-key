package sk.cyberl.certsigner.logging;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;
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
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility for formatting and decoding X.509 certificate extensions into human-readable representations.
 */
public final class ExtensionFormatter {

    private static final Map<ASN1ObjectIdentifier, String> KNOWN_OIDS = new HashMap<>();

    static {
        // Standard X.509 v3 Extensions (RFC 5280)
        KNOWN_OIDS.put(Extension.authorityInfoAccess, "Authority Information Access");
        KNOWN_OIDS.put(Extension.authorityKeyIdentifier, "Authority Key Identifier");
        KNOWN_OIDS.put(Extension.basicConstraints, "Basic Constraints");
        KNOWN_OIDS.put(Extension.biometricInfo, "Biometric Information");
        KNOWN_OIDS.put(Extension.certificateIssuer, "Certificate Issuer");
        KNOWN_OIDS.put(Extension.certificatePolicies, "Certificate Policies");
        KNOWN_OIDS.put(Extension.cRLDistributionPoints, "CRL Distribution Points");
        KNOWN_OIDS.put(Extension.cRLNumber, "CRL Number");
        KNOWN_OIDS.put(Extension.deltaCRLIndicator, "Delta CRL Indicator");
        KNOWN_OIDS.put(Extension.extendedKeyUsage, "Extended Key Usage");
        KNOWN_OIDS.put(Extension.freshestCRL, "Freshest CRL");
        KNOWN_OIDS.put(Extension.inhibitAnyPolicy, "Inhibit Any Policy");
        KNOWN_OIDS.put(Extension.instructionCode, "Instruction Code");
        KNOWN_OIDS.put(Extension.invalidityDate, "Invalidity Date");
        KNOWN_OIDS.put(Extension.issuerAlternativeName, "Issuer Alternative Name");
        KNOWN_OIDS.put(Extension.issuingDistributionPoint, "Issuing Distribution Point");
        KNOWN_OIDS.put(Extension.keyUsage, "Key Usage");
        KNOWN_OIDS.put(Extension.logoType, "Logo Type");
        KNOWN_OIDS.put(Extension.nameConstraints, "Name Constraints");
        KNOWN_OIDS.put(Extension.noRevAvail, "No Revocation Available");
        KNOWN_OIDS.put(Extension.policyConstraints, "Policy Constraints");
        KNOWN_OIDS.put(Extension.policyMappings, "Policy Mappings");
        KNOWN_OIDS.put(Extension.privateKeyUsagePeriod, "Private Key Usage Period");
        KNOWN_OIDS.put(Extension.qCStatements, "QC Statements");
        KNOWN_OIDS.put(Extension.reasonCode, "Reason Code");
        KNOWN_OIDS.put(Extension.subjectAlternativeName, "Subject Alternative Name");
        KNOWN_OIDS.put(Extension.subjectDirectoryAttributes, "Subject Directory Attributes");
        KNOWN_OIDS.put(Extension.subjectInfoAccess, "Subject Information Access");
        KNOWN_OIDS.put(Extension.subjectKeyIdentifier, "Subject Key Identifier");
        KNOWN_OIDS.put(Extension.targetInformation, "Target Information");
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.24"), "TLS Feature (Must-Staple)");
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.4"), "Audit Identity Submission");

        // PKCS#9 Attribute OIDs
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.14"), "Extension Request");
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.7"), "Challenge Password");
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.2"), "Unstructured Name");
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.8"), "Unstructured Address");
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.20"), "Friendly Name");
        KNOWN_OIDS.put(new ASN1ObjectIdentifier("1.2.840.113549.1.9.21"), "Local Key ID");
    }

    private ExtensionFormatter() {
    }

    /**
     * Returns a human-friendly name for a given OID, or its dot-notation string if unknown.
     *
     * @param oid The ASN.1 object identifier.
     * @return Friendly name or OID string.
     */
    public static String getFriendlyName(ASN1ObjectIdentifier oid) {
        if (oid == null) {
            return "Unknown";
        }
        return KNOWN_OIDS.getOrDefault(oid, oid.getId());
    }

    /**
     * Decodes and formats an {@link Extension} into a human-readable string.
     *
     * @param extension The extension to format.
     * @return Formatted human-readable string.
     */
    public static String formatExtensionValue(Extension extension) {
        if (extension == null) {
            return "null";
        }

        ASN1ObjectIdentifier oid = extension.getExtnId();
        try {
            ASN1Encodable parsed = extension.getParsedValue();
            if (parsed == null) {
                return formatHexBytes(extension.getExtnValue().getOctets());
            }

            if (Extension.basicConstraints.equals(oid)) {
                return formatBasicConstraints(BasicConstraints.getInstance(parsed));
            } else if (Extension.keyUsage.equals(oid)) {
                return formatKeyUsage(KeyUsage.getInstance(parsed));
            } else if (Extension.extendedKeyUsage.equals(oid)) {
                return formatExtendedKeyUsage(ExtendedKeyUsage.getInstance(parsed));
            } else if (Extension.subjectAlternativeName.equals(oid) || Extension.issuerAlternativeName.equals(oid)) {
                return formatGeneralNames(GeneralNames.getInstance(parsed));
            } else if (Extension.subjectKeyIdentifier.equals(oid)) {
                return formatSubjectKeyIdentifier(SubjectKeyIdentifier.getInstance(parsed));
            } else if (Extension.authorityKeyIdentifier.equals(oid)) {
                return formatAuthorityKeyIdentifier(AuthorityKeyIdentifier.getInstance(parsed));
            } else if (Extension.cRLDistributionPoints.equals(oid) || Extension.freshestCRL.equals(oid)) {
                return formatCRLDistributionPoints(CRLDistPoint.getInstance(parsed));
            } else if (Extension.authorityInfoAccess.equals(oid) || Extension.subjectInfoAccess.equals(oid)) {
                return formatAccessDescriptions(parsed);
            } else if (Extension.certificatePolicies.equals(oid)) {
                return formatCertificatePolicies(CertificatePolicies.getInstance(parsed));
            } else if (Extension.nameConstraints.equals(oid)) {
                return formatNameConstraints(NameConstraints.getInstance(parsed));
            } else if (Extension.subjectDirectoryAttributes.equals(oid)) {
                return SubjectDirectoryAttributes.getInstance(parsed).toString();
            }

            // Generic ASN.1 fallback
            ASN1Primitive primitive = parsed.toASN1Primitive();
            String dump = ASN1Dump.dumpAsString(primitive, false).trim();
            return dump.isEmpty() ? formatHexBytes(extension.getExtnValue().getOctets()) : dump;
        } catch (Exception _) {
            byte[] octets = extension.getExtnValue() != null ? extension.getExtnValue().getOctets() : new byte[0];
            return formatHexBytes(octets);
        }
    }

    /**
     * Formats {@link BasicConstraints}.
     */
    public static String formatBasicConstraints(BasicConstraints bc) {
        if (bc == null) {
            return "None";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("CA: ").append(bc.isCA() ? "TRUE" : "FALSE");
        if (bc.getPathLenConstraint() != null) {
            sb.append(", PathLenConstraint: ").append(bc.getPathLenConstraint());
        }
        return sb.toString();
    }

    /**
     * Formats {@link KeyUsage}.
     */
    public static String formatKeyUsage(KeyUsage ku) {
        if (ku == null) {
            return "None";
        }
        List<String> usages = new ArrayList<>();
        if (ku.hasUsages(KeyUsage.digitalSignature)) usages.add("Digital Signature");
        if (ku.hasUsages(KeyUsage.nonRepudiation)) usages.add("Non-Repudiation / Content Commitment");
        if (ku.hasUsages(KeyUsage.keyEncipherment)) usages.add("Key Encipherment");
        if (ku.hasUsages(KeyUsage.dataEncipherment)) usages.add("Data Encipherment");
        if (ku.hasUsages(KeyUsage.keyAgreement)) usages.add("Key Agreement");
        if (ku.hasUsages(KeyUsage.keyCertSign)) usages.add("Certificate Sign");
        if (ku.hasUsages(KeyUsage.cRLSign)) usages.add("CRL Sign");
        if (ku.hasUsages(KeyUsage.encipherOnly)) usages.add("Encipher Only");
        if (ku.hasUsages(KeyUsage.decipherOnly)) usages.add("Decipher Only");
        return usages.isEmpty() ? "None (0x00)" : String.join(", ", usages);
    }

    /**
     * Formats {@link ExtendedKeyUsage}.
     */
    public static String formatExtendedKeyUsage(ExtendedKeyUsage eku) {
        if (eku == null) {
            return "None";
        }
        List<String> list = new ArrayList<>();
        for (KeyPurposeId id : eku.getUsages()) {
            String oidStr = id.getId();
            String name = getExtendedKeyUsageName(oidStr);
            list.add(name != null ? name + " (" + oidStr + ")" : oidStr);
        }
        return list.isEmpty() ? "None" : String.join(", ", list);
    }

    private static String getExtendedKeyUsageName(String oid) {
        return switch (oid) {
            case "1.3.6.1.5.5.7.3.1" -> "TLS Web Server Authentication (serverAuth)";
            case "1.3.6.1.5.5.7.3.2" -> "TLS Web Client Authentication (clientAuth)";
            case "1.3.6.1.5.5.7.3.3" -> "Code Signing (codeSigning)";
            case "1.3.6.1.5.5.7.3.4" -> "E-mail Protection (emailProtection)";
            case "1.3.6.1.5.5.7.3.5" -> "IP security End System (ipsecEndSystem)";
            case "1.3.6.1.5.5.7.3.6" -> "IP security Tunnel (ipsecTunnel)";
            case "1.3.6.1.5.5.7.3.7" -> "IP security User (ipsecUser)";
            case "1.3.6.1.5.5.7.3.8" -> "Time Stamping (timeStamping)";
            case "1.3.6.1.5.5.7.3.9" -> "OCSP Signing (OCSPSigning)";
            case "1.3.6.1.5.5.7.3.13" -> "EAP Over PPP (eapOverPPP)";
            case "1.3.6.1.5.5.7.3.14" -> "EAP Over LAN (eapOverLAN)";
            case "2.5.29.37.0" -> "Any Extended Key Usage";
            case "1.3.6.1.4.1.311.10.3.3" -> "Microsoft Server Gated Crypto";
            case "2.16.840.1.113730.4.1" -> "Netscape Server Gated Crypto";
            case "1.3.6.1.4.1.311.20.2.2" -> "Smartcard Logon";
            default -> null;
        };
    }

    /**
     * Formats {@link GeneralNames} (e.g. for SAN / IAN).
     */
    public static String formatGeneralNames(GeneralNames generalNames) {
        if (generalNames == null || generalNames.getNames() == null) {
            return "None";
        }
        List<String> list = new ArrayList<>();
        for (GeneralName gn : generalNames.getNames()) {
            list.add(formatGeneralName(gn));
        }
        return list.isEmpty() ? "None" : String.join(", ", list);
    }

    /**
     * Formats a single {@link GeneralName}.
     */
    public static String formatGeneralName(GeneralName gn) {
        if (gn == null) {
            return "null";
        }
        int tag = gn.getTagNo();
        ASN1Encodable name = gn.getName();
        return switch (tag) {
            case GeneralName.otherName -> "OtherName:" + name;
            case GeneralName.rfc822Name -> "Email:" + name;
            case GeneralName.dNSName -> "DNS:" + name;
            case GeneralName.x400Address -> "X400:" + name;
            case GeneralName.directoryName -> "DirName:" + name;
            case GeneralName.ediPartyName -> "EDI:" + name;
            case GeneralName.uniformResourceIdentifier -> "URI:" + name;
            case GeneralName.iPAddress -> {
                if (name instanceof ASN1OctetString octetString) {
                    try {
                        yield "IP:" + InetAddress.getByAddress(octetString.getOctets()).getHostAddress();
                    } catch (Exception _) {
                        yield "IP:" + formatHexBytes(octetString.getOctets());
                    }
                }
                yield "IP:" + name;
            }
            case GeneralName.registeredID -> "RegisteredID:" + name;
            default -> "Tag" + tag + ":" + name;
        };
    }

    /**
     * Formats {@link SubjectKeyIdentifier}.
     */
    public static String formatSubjectKeyIdentifier(SubjectKeyIdentifier ski) {
        if (ski == null || ski.getKeyIdentifier() == null) {
            return "None";
        }
        return formatHexBytes(ski.getKeyIdentifier());
    }

    /**
     * Formats {@link AuthorityKeyIdentifier}.
     */
    public static String formatAuthorityKeyIdentifier(AuthorityKeyIdentifier aki) {
        if (aki == null) {
            return "None";
        }
        List<String> parts = new ArrayList<>();
        if (aki.getKeyIdentifier() != null) {
            parts.add("KeyID: " + formatHexBytes(aki.getKeyIdentifier()));
        }
        if (aki.getAuthorityCertIssuer() != null) {
            parts.add("CertIssuer: " + formatGeneralNames(aki.getAuthorityCertIssuer()));
        }
        if (aki.getAuthorityCertSerialNumber() != null) {
            parts.add("CertSerial: " + aki.getAuthorityCertSerialNumber().toString(16).toUpperCase());
        }
        return parts.isEmpty() ? "Empty" : String.join(", ", parts);
    }

    /**
     * Formats {@link CRLDistPoint}.
     */
    public static String formatCRLDistributionPoints(CRLDistPoint cdp) {
        if (cdp == null || cdp.getDistributionPoints() == null) {
            return "None";
        }
        List<String> list = new ArrayList<>();
        for (DistributionPoint dp : cdp.getDistributionPoints()) {
            DistributionPointName dpName = dp.getDistributionPoint();
            if (dpName != null && dpName.getType() == DistributionPointName.FULL_NAME) {
                GeneralNames gns = GeneralNames.getInstance(dpName.getName());
                list.add(formatGeneralNames(gns));
            } else if (dpName != null) {
                list.add(dpName.getName().toString());
            }
        }
        return list.isEmpty() ? "None" : String.join("; ", list);
    }

    /**
     * Formats Access Descriptions (AIA / SIA).
     */
    public static String formatAccessDescriptions(ASN1Encodable encodable) {
        if (encodable == null) {
            return "None";
        }
        try {
            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(encodable);
            if (aia.getAccessDescriptions() == null) {
                return "None";
            }
            List<String> list = new ArrayList<>();
            for (AccessDescription desc : aia.getAccessDescriptions()) {
                String method = AccessDescription.id_ad_ocsp.equals(desc.getAccessMethod()) ? "OCSP" :
                                AccessDescription.id_ad_caIssuers.equals(desc.getAccessMethod()) ? "CA Issuers" :
                                desc.getAccessMethod().getId();
                list.add(method + " -> " + formatGeneralName(desc.getAccessLocation()));
            }
            return list.isEmpty() ? "None" : String.join(", ", list);
        } catch (Exception _) {
            return encodable.toString();
        }
    }

    /**
     * Formats {@link CertificatePolicies}.
     */
    public static String formatCertificatePolicies(CertificatePolicies cp) {
        if (cp == null || cp.getPolicyInformation() == null) {
            return "None";
        }
        List<String> list = new ArrayList<>();
        for (PolicyInformation pi : cp.getPolicyInformation()) {
            StringBuilder sb = new StringBuilder();
            sb.append("Policy: ").append(pi.getPolicyIdentifier().getId());
            ASN1Sequence qualifiers = pi.getPolicyQualifiers();
            if (qualifiers != null) {
                for (ASN1Encodable q : qualifiers) {
                    try {
                        PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(q);
                        if (PolicyQualifierId.id_qt_cps.equals(pqi.getPolicyQualifierId())) {
                            sb.append(" [CPS: ").append(pqi.getQualifier()).append("]");
                        } else if (PolicyQualifierId.id_qt_unotice.equals(pqi.getPolicyQualifierId())) {
                            sb.append(" [UserNotice: ").append(pqi.getQualifier()).append("]");
                        } else {
                            sb.append(" [Qualifier: ").append(pqi.getPolicyQualifierId().getId()).append("]");
                        }
                    } catch (Exception _) {
                    }
                }
            }
            list.add(sb.toString());
        }
        return list.isEmpty() ? "None" : String.join("; ", list);
    }

    /**
     * Formats {@link NameConstraints}.
     */
    public static String formatNameConstraints(NameConstraints nc) {
        if (nc == null) {
            return "None";
        }
        StringBuilder sb = new StringBuilder();
        if (nc.getPermittedSubtrees() != null) {
            List<String> permitted = new ArrayList<>();
            for (GeneralSubtree st : nc.getPermittedSubtrees()) {
                permitted.add(formatGeneralName(st.getBase()));
            }
            sb.append("Permitted: [").append(String.join(", ", permitted)).append("]");
        }
        if (nc.getExcludedSubtrees() != null) {
            if (!sb.isEmpty()) sb.append(", ");
            List<String> excluded = new ArrayList<>();
            for (GeneralSubtree st : nc.getExcludedSubtrees()) {
                excluded.add(formatGeneralName(st.getBase()));
            }
            sb.append("Excluded: [").append(String.join(", ", excluded)).append("]");
        }
        return sb.isEmpty() ? "None" : sb.toString();
    }

    /**
     * Formats raw bytes into a colon-separated uppercase hex string (e.g. {@code 3F:A1:0B:...}).
     *
     * @param bytes Byte array.
     * @return Formatted hex string.
     */
    public static String formatHexBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "None";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
}
