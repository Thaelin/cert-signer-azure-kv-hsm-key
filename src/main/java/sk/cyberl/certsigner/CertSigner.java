package sk.cyberl.certsigner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import sk.cyberl.certsigner.config.CertSignerConfig;

public class CertSigner {

    private final CertSignerConfig config;

    public CertSigner(CertSignerConfig config) {
        this.config = config;
    }

    public byte[] signCert() {
        X500Name subjectDn;
        ASN1Set attributes;

        if (config.certCsrPath() != null && config.certCsrPath().isEmpty()) {
            CertificationRequestInfo csrInfo = parseCsr();
            subjectDn = csrInfo.getSubject();
            attributes = csrInfo.getAttributes();
        } else {
            // TODO: Handle the case when no CSR is provided. 
        }
        



        return null;
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

}
