package sk.cyberl.certsigner.azure;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class AzureKeyVaultContentSignerTest {

    @Test
    void testConvertP1363ToDerWithP256() throws Exception {
        // 64-byte P1363 signature for ES256 (32 bytes r, 32 bytes s)
        byte[] p1363Sig = new byte[64];
        Arrays.fill(p1363Sig, 0, 32, (byte) 0x11);
        Arrays.fill(p1363Sig, 32, 64, (byte) 0x22);

        byte[] derSignature = AzureKeyVaultContentSigner.convertP1363ToDer(p1363Sig);
        assertNotNull(derSignature);

        // Parse DER sequence and verify r and s
        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(derSignature))) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            assertEquals(2, seq.size());
            ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
            ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);

            BigInteger expectedR = new BigInteger(1, Arrays.copyOfRange(p1363Sig, 0, 32));
            BigInteger expectedS = new BigInteger(1, Arrays.copyOfRange(p1363Sig, 32, 64));

            assertEquals(expectedR, r.getValue());
            assertEquals(expectedS, s.getValue());
        }
    }

    @Test
    void testConvertP1363ToDerWithP384() throws Exception {
        // 96-byte P1363 signature for ES384 (48 bytes r, 48 bytes s)
        byte[] p1363Sig = new byte[96];
        Arrays.fill(p1363Sig, 0, 48, (byte) 0x33);
        Arrays.fill(p1363Sig, 48, 96, (byte) 0x44);

        byte[] derSignature = AzureKeyVaultContentSigner.convertP1363ToDer(p1363Sig);
        assertNotNull(derSignature);

        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(derSignature))) {
            ASN1Sequence seq = (ASN1Sequence) in.readObject();
            assertEquals(2, seq.size());
            ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
            ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);

            BigInteger expectedR = new BigInteger(1, Arrays.copyOfRange(p1363Sig, 0, 48));
            BigInteger expectedS = new BigInteger(1, Arrays.copyOfRange(p1363Sig, 48, 96));

            assertEquals(expectedR, r.getValue());
            assertEquals(expectedS, s.getValue());
        }
    }

    @Test
    void testConvertP1363ToDerInvalidLengthThrows() {
        assertThrows(IllegalArgumentException.class, () -> AzureKeyVaultContentSigner.convertP1363ToDer(null));
        assertThrows(IllegalArgumentException.class, () -> AzureKeyVaultContentSigner.convertP1363ToDer(new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> AzureKeyVaultContentSigner.convertP1363ToDer(new byte[7]));
    }

    @Test
    void testAlgorithmIdentifierFinder() {
        AlgorithmIdentifier rsaAlg = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        assertNotNull(rsaAlg);

        AlgorithmIdentifier ecAlg = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
        assertNotNull(ecAlg);
    }
}
