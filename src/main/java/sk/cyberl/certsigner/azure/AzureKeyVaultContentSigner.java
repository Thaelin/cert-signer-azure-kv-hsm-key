package sk.cyberl.certsigner.azure;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Bouncy Castle {@link ContentSigner} implementation that signs certificate
 * data using an Azure Key Vault HSM key via {@link CryptographyClient}.
 */
public class AzureKeyVaultContentSigner implements ContentSigner {

    private final CryptographyClient cryptographyClient;
    private final SignatureAlgorithm signatureAlgorithm;
    private final AlgorithmIdentifier algorithmIdentifier;
    private final boolean isEc;
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    public AzureKeyVaultContentSigner(
            CryptographyClient cryptographyClient,
            SignatureAlgorithm signatureAlgorithm,
            AlgorithmIdentifier algorithmIdentifier,
            boolean isEc) {
        this.cryptographyClient = Objects.requireNonNull(cryptographyClient, "cryptographyClient must not be null");
        this.signatureAlgorithm = Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm must not be null");
        this.algorithmIdentifier = Objects.requireNonNull(algorithmIdentifier, "algorithmIdentifier must not be null");
        this.isEc = isEc;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return outputStream;
    }

    @Override
    public byte[] getSignature() {
        try {
            byte[] dataToSign = outputStream.toByteArray();
            SignResult signResult = cryptographyClient.signData(signatureAlgorithm, dataToSign);
            byte[] rawSignature = signResult.getSignature();

            if (isEc) {
                return convertP1363ToDer(rawSignature);
            }
            return rawSignature;
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign data using Azure Key Vault key", e);
        }
    }

    /**
     * Converts an IEEE P1363 (r || s) formatted ECDSA signature to an ASN.1 DER-encoded SEQUENCE.
     * Azure Key Vault returns ECDSA signatures in IEEE P1363 format, whereas X.509 certificates
     * (RFC 5280) require ASN.1 DER encoding.
     *
     * @param p1363Signature Raw (r || s) signature bytes
     * @return DER-encoded ASN.1 sequence containing r and s integers
     */
    public static byte[] convertP1363ToDer(byte[] p1363Signature) {
        if (p1363Signature == null || p1363Signature.length % 2 != 0 || p1363Signature.length == 0) {
            throw new IllegalArgumentException("Invalid IEEE P1363 signature length: " + 
                    (p1363Signature == null ? "null" : p1363Signature.length));
        }

        int halfLength = p1363Signature.length / 2;
        byte[] rBytes = Arrays.copyOfRange(p1363Signature, 0, halfLength);
        byte[] sBytes = Arrays.copyOfRange(p1363Signature, halfLength, p1363Signature.length);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));

        try {
            return new DERSequence(vector).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException("Failed to DER encode ECDSA signature components", e);
        }
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public boolean isEc() {
        return isEc;
    }
}
