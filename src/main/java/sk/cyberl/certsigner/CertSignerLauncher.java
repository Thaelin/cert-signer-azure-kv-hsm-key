package sk.cyberl.certsigner;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import sk.cyberl.certsigner.config.CertSignerConfig;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.concurrent.Callable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Command(
    name = "cert-signer",
    mixinStandardHelpOptions = true,
    version = "cert-signer 1.0.0",
    description = "Signs certificates using Azure Key Vault HSM keys.",
    usageHelpAutoWidth = true
)
public class CertSignerLauncher implements Callable<Integer> {

    @Option(
        names = {"-o", "--output-cert-path"},
        required = true,
        paramLabel = "<path>",
        description = "Path to the output certificate file."
    )
    private String outputCertPath;

    @Option(
        names = {"-r", "--cert-csr-path"},
        paramLabel = "<path>",
        description = "Path to the certificate signing request (CSR) file."
    )
    private String certCsrPath;

    @Option(
        names = {"-s", "--cert-subject-dn"},
        paramLabel = "<dn>",
        description = "Certificate Subject Distinguished Name (e.g. 'CN=example.com,O=Org,C=US')."
    )
    private String certSubjectDn;

    @Option(
        names = {"-p", "--cert-public-key-path"},
        paramLabel = "<path>",
        description = "Path to the subject public key file."
    )
    private String certPublicKeyPath;

    @Option(
        names = {"-a", "--cert-attributes"},
        paramLabel = "<attributes>",
        description = "Certificate attributes (path to ASN.1 DER file or Base64 encoded ASN.1)."
    )
    private String certAttributes;

    @Option(
        names = {"-d", "--validity-days", "--validity-period"},
        paramLabel = "<days>",
        defaultValue = "365",
        description = "Certificate validity period in days (default: 365)."
    )
    private Integer validityDays = 365;

    @Option(
        names = {"-v", "--kv-name"},
        required = true,
        paramLabel = "<name>",
        description = "Azure Key Vault name."
    )
    private String kvName;

    @Option(
        names = {"-k", "--kv-key-name"},
        required = true,
        paramLabel = "<name>",
        description = "Key Vault key name."
    )
    private String kvKeyName;

    @Option(
        names = {"-e", "--kv-key-version"},
        required = true,
        paramLabel = "<version>",
        description = "Key Vault key version."
    )
    private String kvKeyVersion;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public Integer call() throws Exception {
        validateInputs();

        var certSigner = new CertSigner(
            new CertSignerConfig(
                outputCertPath, 
                certCsrPath,
                certSubjectDn,
                certPublicKeyPath,
                certAttributes,
                validityDays,
                kvName, 
                kvKeyName, 
                kvKeyVersion
            )
        );

        byte[] signedCert = certSigner.signCert();

        if (signedCert != null) {
            Files.write(Path.of(outputCertPath), signedCert);
        }

        return CommandLine.ExitCode.OK;
    }

    private void validateInputs() {
        boolean hasCsr = certCsrPath != null && !certCsrPath.isBlank();
        boolean hasDirectSubject = certSubjectDn != null && !certSubjectDn.isBlank();
        boolean hasPublicKey = certPublicKeyPath != null && !certPublicKeyPath.isBlank();

        if (!hasCsr && !hasDirectSubject) {
            throw new CommandLine.ParameterException(
                new CommandLine(this),
                "Either --cert-csr-path (-r) or --cert-subject-dn (-s) with --cert-public-key-path (-p) must be provided."
            );
        }

        if (hasDirectSubject && !hasPublicKey) {
            throw new CommandLine.ParameterException(
                new CommandLine(this),
                "When --cert-subject-dn (-s) is provided, --cert-public-key-path (-p) must also be specified."
            );
        }
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new CertSignerLauncher()).execute(args);
        System.exit(exitCode);
    }

    public String getOutputCertPath() {
        return outputCertPath;
    }

    public String getCertCsrPath() {
        return certCsrPath;
    }

    public String getCertSubjectDn() {
        return certSubjectDn;
    }

    public String getCertPublicKeyPath() {
        return certPublicKeyPath;
    }

    public String getCertAttributes() {
        return certAttributes;
    }

    public Integer getValidityDays() {
        return validityDays;
    }

    public String getKvName() {
        return kvName;
    }

    public String getKvKeyName() {
        return kvKeyName;
    }

    public String getKvKeyVersion() {
        return kvKeyVersion;
    }
}