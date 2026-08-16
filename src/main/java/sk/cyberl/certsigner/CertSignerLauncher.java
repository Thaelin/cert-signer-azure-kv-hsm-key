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
        required = true,
        paramLabel = "<path>",
        description = "Path to the certificate signing request (CSR) file."
    )
    private String certCsrPath;

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
        var certSigner = new CertSigner(
            new CertSignerConfig(
                outputCertPath, 
                certCsrPath, 
                kvName, 
                kvKeyName, 
                kvKeyVersion
            )
        );

        byte[] signedCert = certSigner.signCert();

        Files.write(Path.of(outputCertPath), signedCert);

        return CommandLine.ExitCode.OK;
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