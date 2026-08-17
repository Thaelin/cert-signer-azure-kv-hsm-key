package sk.cyberl.certsigner.logging;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

/**
 * Tracks, formats, and logs all certificate attributes, metadata, and extensions
 * along with their explicit provenance sources (CSR, CLI, DEFAULT, KEY_VAULT).
 */
public class CertificateAttributeLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateAttributeLogger.class);

    private final List<TrackedAttribute> attributes = new ArrayList<>();
    private final Map<ASN1ObjectIdentifier, TrackedExtension> extensions = new LinkedHashMap<>();
    private final List<TrackedCsrAttribute> csrAttributes = new ArrayList<>();

    /**
     * Record representing a tracked certificate attribute (Subject, Issuer, Validity, etc.).
     *
     * @param name    Attribute display name.
     * @param value   Attribute value string.
     * @param source  Provenance source.
     * @param details Optional additional details.
     */
    public record TrackedAttribute(
            String name,
            String value,
            AttributeSource source,
            String details
    ) { }

    /**
     * Record representing a tracked X.509 certificate extension.
     *
     * @param oid            Extension Object Identifier.
     * @param friendlyName   Friendly human-readable extension name.
     * @param critical       Whether the extension is flagged critical.
     * @param formattedValue Formatted string representation of the extension value.
     * @param source         Provenance source.
     */
    public record TrackedExtension(
            ASN1ObjectIdentifier oid,
            String friendlyName,
            boolean critical,
            String formattedValue,
            AttributeSource source
    ) { }

    /**
     * Record representing a tracked non-extension CSR attribute (e.g. challengePassword).
     *
     * @param typeOid        Attribute Type Object Identifier.
     * @param typeName       Friendly name or OID string.
     * @param formattedValue Formatted value string.
     * @param source         Provenance source.
     */
    public record TrackedCsrAttribute(
            ASN1ObjectIdentifier typeOid,
            String typeName,
            String formattedValue,
            AttributeSource source
    ) { }

    /**
     * Adds a basic certificate attribute.
     *
     * @param name   Attribute display name.
     * @param value  Attribute value string.
     * @param source Provenance source.
     */
    public void addAttribute(String name, String value, AttributeSource source) {
        addAttribute(name, value, source, null);
    }

    /**
     * Adds a basic certificate attribute with additional details.
     *
     * @param name    Attribute display name.
     * @param value   Attribute value string.
     * @param source  Provenance source.
     * @param details Additional detail string.
     */
    public void addAttribute(String name, String value, AttributeSource source, String details) {
        attributes.add(new TrackedAttribute(name, value, source, details));
    }

    /**
     * Formats and records Subject Public Key Information.
     *
     * @param spki   The subject public key info.
     * @param source Provenance source.
     */
    public void addPublicKey(SubjectPublicKeyInfo spki, AttributeSource source) {
        if (spki == null) {
            addAttribute("Public Key", "None", source);
            return;
        }

        String keyDescription = formatPublicKeyInfo(spki);
        addAttribute("Public Key", keyDescription, source);
    }

    /**
     * Formats and records certificate validity timestamps.
     *
     * @param notBefore      Start of validity.
     * @param notAfter       End of validity.
     * @param validityDays   Configured or defaulted validity period in days.
     * @param validitySource Source of validity duration (CLI or DEFAULT).
     */
    public void addValidity(Date notBefore, Date notAfter, int validityDays, AttributeSource validitySource) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));

        addAttribute("Validity Not Before", sdf.format(notBefore), AttributeSource.DEFAULT);
        addAttribute("Validity Not After",
                String.format("%s (%d days)", sdf.format(notAfter), validityDays),
                validitySource
        );
    }

    /**
     * Adds a tracked extension. If an extension with the same OID was already registered,
     * it will be updated (e.g. CLI overriding CSR).
     *
     * @param extension The X.509 extension.
     * @param source    Provenance source.
     */
    public void addExtension(Extension extension, AttributeSource source) {
        if (extension == null) {
            return;
        }
        ASN1ObjectIdentifier oid = extension.getExtnId();
        String friendlyName = ExtensionFormatter.getFriendlyName(oid);
        String formattedValue = ExtensionFormatter.formatExtensionValue(extension);
        extensions.put(oid, new TrackedExtension(oid, friendlyName, extension.isCritical(), formattedValue, source));
    }

    /**
     * Adds a tracked extension with explicitly provided fields.
     *
     * @param oid            Extension OID.
     * @param critical       Criticality flag.
     * @param formattedValue Decoded value string.
     * @param source         Provenance source.
     */
    public void addExtension(ASN1ObjectIdentifier oid, boolean critical, String formattedValue, AttributeSource source) {
        String friendlyName = ExtensionFormatter.getFriendlyName(oid);
        extensions.put(oid, new TrackedExtension(oid, friendlyName, critical, formattedValue, source));
    }

    /**
     * Processes an ASN.1 set of attributes from a CSR or CLI, registering any contained extensions
     * or non-extension attributes.
     *
     * @param attributeSet The ASN.1 set of attributes.
     * @param source       Provenance source (e.g. CSR or CLI).
     */
    public void processAttributeSet(ASN1Set attributeSet, AttributeSource source) {
        if (attributeSet == null) {
            return;
        }

        for (ASN1Encodable encodable : attributeSet.toArray()) {
            if (encodable instanceof Extension ext) {
                addExtension(ext, source);
                continue;
            }

            try {
                Attribute attr = Attribute.getInstance(encodable);
                ASN1ObjectIdentifier typeOid = attr.getAttrType();

                if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(typeOid)) {
                    ASN1Set attrValues = attr.getAttrValues();
                    if (attrValues != null && attrValues.size() > 0) {
                        ASN1Encodable val = attrValues.getObjectAt(0);
                        org.bouncycastle.asn1.x509.Extensions exts = org.bouncycastle.asn1.x509.Extensions.getInstance(val);
                        for (ASN1ObjectIdentifier extOid : exts.getExtensionOIDs()) {
                            addExtension(exts.getExtension(extOid), source);
                        }
                    }
                } else {
                    // Non-extension CSR attribute
                    String typeName = ExtensionFormatter.getFriendlyName(typeOid);
                    String valStr = attr.getAttrValues() != null ? attr.getAttrValues().toString() : "None";
                    csrAttributes.add(new TrackedCsrAttribute(typeOid, typeName, valStr, source));
                }
            } catch (Exception e) {
                LOGGER.warn("There was a problem when processing attribute: " + encodable, e);
            }
        }
    }

    /**
     * Generates a formatted multi-line summary of all certificate attributes, extensions,
     * and their provenance sources.
     *
     * @return Formatted report string.
     */
    public String buildReport() {
        StringBuilder sb = new StringBuilder();
        String line = "=".repeat(80);
        String subline = "-".repeat(80);

        sb.append(System.lineSeparator());
        sb.append(line).append(System.lineSeparator());
        sb.append("                    CERTIFICATE ATTRIBUTES & PROVENANCE").append(System.lineSeparator());
        sb.append(line).append(System.lineSeparator());

        // Basic Attributes
        for (TrackedAttribute attr : attributes) {
            String sourceTag = String.format("%-11s", attr.source().getTag());
            String nameStr = String.format("%-23s", attr.name() + ":");
            sb.append(sourceTag).append(nameStr).append(attr.value());
            if (attr.details() != null && !attr.details().isBlank()) {
                sb.append(" (").append(attr.details()).append(")");
            }
            sb.append(System.lineSeparator());
        }

        // Extensions Section
        sb.append(System.lineSeparator()).append(subline).append(System.lineSeparator());
        sb.append(String.format("CERTIFICATE EXTENSIONS (%d)", extensions.size())).append(System.lineSeparator());
        sb.append(subline).append(System.lineSeparator());

        if (extensions.isEmpty()) {
            sb.append("  (None)").append(System.lineSeparator());
        } else {
            int index = 1;
            for (TrackedExtension ext : extensions.values()) {
                sb.append(String.format("%d. %s %s (%s)",
                        index++,
                        ext.source().getTag(),
                        ext.friendlyName(),
                        ext.oid().getId()
                )).append(System.lineSeparator());
                sb.append(String.format("   Critical: %s", ext.critical() ? "TRUE" : "FALSE")).append(System.lineSeparator());
                sb.append(String.format("   Value:    %s", ext.formattedValue())).append(System.lineSeparator());
                sb.append(System.lineSeparator());
            }
        }

        // CSR Non-Extension Attributes Section (if any)
        if (!csrAttributes.isEmpty()) {
            sb.append(subline).append(System.lineSeparator());
            sb.append(String.format("CSR ATTRIBUTES (%d)", csrAttributes.size())).append(System.lineSeparator());
            sb.append(subline).append(System.lineSeparator());

            int idx = 1;
            for (TrackedCsrAttribute attr : csrAttributes) {
                sb.append(String.format("%d. %s %s (%s)",
                        idx++,
                        attr.source().getTag(),
                        attr.typeName(),
                        attr.typeOid().getId()
                )).append(System.lineSeparator());
                sb.append(String.format("   Value: %s", attr.formattedValue())).append(System.lineSeparator());
            }
        }

        sb.append(line);
        return sb.toString();
    }

    /**
     * Logs the full formatted certificate report using SLF4J at {@code INFO} level.
     */
    public void logReport() {
        LOGGER.info(buildReport());
    }

    /**
     * Formats public key details into an informative string (e.g. RSA 2048-bit or EC secp256r1).
     *
     * @param spki SubjectPublicKeyInfo.
     * @return Formatted key string.
     */
    public static String formatPublicKeyInfo(SubjectPublicKeyInfo spki) {
        try {
            org.bouncycastle.crypto.params.AsymmetricKeyParameter keyParam = PublicKeyFactory.createKey(spki);
            if (keyParam instanceof RSAKeyParameters rsa) {
                return String.format("RSA %d-bit (Exponent: %s)", rsa.getModulus().bitLength(), rsa.getExponent());
            } else if (keyParam instanceof ECPublicKeyParameters ec) {
                String curveName = null;
                ASN1Encodable params = spki.getAlgorithm().getParameters();
                if (params instanceof ASN1ObjectIdentifier oid) {
                    curveName = ECNamedCurveTable.getName(oid);
                }
                if (curveName == null) {
                    curveName = "EC " + ec.getParameters().getCurve().getFieldSize() + "-bit";
                }
                return String.format("EC %s (%d-bit)", curveName, ec.getParameters().getCurve().getFieldSize());
            }
            return spki.getAlgorithm().getAlgorithm().getId();
        } catch (Exception _) {
            return spki.getAlgorithm().getAlgorithm().getId();
        }
    }

    /**
     * Returns an unmodifiable list of tracked attributes.
     *
     * @return List of attributes.
     */
    public List<TrackedAttribute> getAttributes() {
        return Collections.unmodifiableList(attributes);
    }

    /**
     * Returns an unmodifiable map of tracked extensions.
     *
     * @return Map of extensions keyed by OID.
     */
    public Map<ASN1ObjectIdentifier, TrackedExtension> getExtensions() {
        return Collections.unmodifiableMap(extensions);
    }

    /**
     * Returns an unmodifiable list of tracked CSR non-extension attributes.
     *
     * @return List of CSR attributes.
     */
    public List<TrackedCsrAttribute> getCsrAttributes() {
        return Collections.unmodifiableList(csrAttributes);
    }
}
