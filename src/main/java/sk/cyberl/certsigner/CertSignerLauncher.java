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

/**
 * Command-line interface launcher for signing certificates using Azure Key Vault HSM keys.
 */
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

    /**
     * Default constructor for {@code CertSignerLauncher}.
     */
    public CertSignerLauncher() {
    }

    /**
     * Executes the certificate signing process from the parsed command-line arguments.
     *
     * @return Process exit code (0 for success).
     * @throws Exception if validation fails or certificate signing encounters an error.
     */
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

    /**
     * Validates that required mutually dependent or alternative CLI options are present.
     *
     * @throws CommandLine.ParameterException if required option combinations are missing.
     */
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

    /**
     * Main entry point for the command-line application.
     *
     * @param args Command-line arguments.
     */
    public static void main(String[] args) {
        int exitCode = new CommandLine(new CertSignerLauncher()).execute(args);
        System.exit(exitCode);
    }

    /**
     * Returns the output certificate path.
     *
     * @return Output certificate path.
     */
    public String getOutputCertPath() {
        return outputCertPath;
    }

    /**
     * Returns the CSR file path.
     *
     * @return CSR file path.
     */
    public String getCertCsrPath() {
        return certCsrPath;
    }

    /**
     * Returns the certificate Subject Distinguished Name.
     *
     * @return Subject DN string.
     */
    public String getCertSubjectDn() {
        return certSubjectDn;
    }

    /**
     * Returns the public key file path.
     *
     * @return Public key file path.
     */
    public String getCertPublicKeyPath() {
        return certPublicKeyPath;
    }

    /**
     * Returns the certificate attributes file path or Base64 string.
     *
     * @return Certificate attributes.
     */
    public String getCertAttributes() {
        return certAttributes;
    }

    /**
     * Returns the certificate validity period in days.
     *
     * @return Validity period in days.
     */
    public Integer getValidityDays() {
        return validityDays;
    }

    /**
     * Returns the Azure Key Vault name.
     *
     * @return Key Vault name.
     */
    public String getKvName() {
        return kvName;
    }

    /**
     * Returns the Azure Key Vault key name.
     *
     * @return Key Vault key name.
     */
    public String getKvKeyName() {
        return kvKeyName;
    }

    /**
     * Returns the Azure Key Vault key version.
     *
     * @return Key Vault key version.
     */
    public String getKvKeyVersion() {
        return kvKeyVersion;
    }
}