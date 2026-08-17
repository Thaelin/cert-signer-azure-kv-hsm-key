package sk.cyberl.certsigner;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import picocli.CommandLine.MissingParameterException;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.UnmatchedArgumentException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link CertSignerLauncher} command-line argument parsing and validation.
 */
class CertSignerLauncherTest {

    /**
     * Tests parsing valid command-line arguments when a CSR file is specified.
     */
    @Test
    void testParseValidArgumentsWithCsr() {
        String[] args = {
            "--output-cert-path", "cert.pem",
            "--cert-csr-path", "csr.pem",
            "--kv-name", "my-vault",
            "--kv-key-name", "my-key",
            "--kv-key-version", "v1"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        cmd.parseArgs(args);

        assertEquals("cert.pem", certSigner.getOutputCertPath());
        assertEquals("csr.pem", certSigner.getCertCsrPath());
        assertEquals("my-vault", certSigner.getKvName());
        assertEquals("my-key", certSigner.getKvKeyName());
        assertEquals("v1", certSigner.getKvKeyVersion());
        assertEquals(365, certSigner.getValidityDays());
    }

    /**
     * Tests parsing valid command-line arguments when specifying direct Subject DN and public key path.
     */
    @Test
    void testParseValidArgumentsWithSubjectDnAndPublicKey() {
        String[] args = {
            "--output-cert-path", "cert.pem",
            "--cert-subject-dn", "CN=example.com,O=My Org,C=US",
            "--cert-public-key-path", "pubkey.pem",
            "--cert-attributes", "attrs.der",
            "--validity-days", "730",
            "--kv-name", "my-vault",
            "--kv-key-name", "my-key",
            "--kv-key-version", "v1"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        cmd.parseArgs(args);

        assertEquals("cert.pem", certSigner.getOutputCertPath());
        assertEquals("CN=example.com,O=My Org,C=US", certSigner.getCertSubjectDn());
        assertEquals("pubkey.pem", certSigner.getCertPublicKeyPath());
        assertEquals("attrs.der", certSigner.getCertAttributes());
        assertEquals(730, certSigner.getValidityDays());
        assertEquals("my-vault", certSigner.getKvName());
        assertEquals("my-key", certSigner.getKvKeyName());
        assertEquals("v1", certSigner.getKvKeyVersion());
    }

    /**
     * Tests parsing command-line arguments using the {@code --option=value} syntax.
     */
    @Test
    void testParseWithEqualsSyntax() {
        String[] args = {
            "--output-cert-path=cert.pem",
            "--cert-csr-path=csr.pem",
            "--validity-period=180",
            "--kv-name=my-vault",
            "--kv-key-name=my-key",
            "--kv-key-version=v1"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        cmd.parseArgs(args);

        assertEquals("cert.pem", certSigner.getOutputCertPath());
        assertEquals("csr.pem", certSigner.getCertCsrPath());
        assertEquals(180, certSigner.getValidityDays());
        assertEquals("my-vault", certSigner.getKvName());
        assertEquals("my-key", certSigner.getKvKeyName());
        assertEquals("v1", certSigner.getKvKeyVersion());
    }

    /**
     * Tests parsing command-line arguments using short options (e.g. {@code -o}, {@code -s}, {@code -p}).
     */
    @Test
    void testParseWithShortOptions() {
        String[] args = {
            "-o", "cert.pem",
            "-s", "CN=test",
            "-p", "pubkey.pem",
            "-a", "attrs.der",
            "-d", "90",
            "-v", "my-vault",
            "-k", "my-key",
            "-e", "v1"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        cmd.parseArgs(args);

        assertEquals("cert.pem", certSigner.getOutputCertPath());
        assertEquals("CN=test", certSigner.getCertSubjectDn());
        assertEquals("pubkey.pem", certSigner.getCertPublicKeyPath());
        assertEquals("attrs.der", certSigner.getCertAttributes());
        assertEquals(90, certSigner.getValidityDays());
        assertEquals("my-vault", certSigner.getKvName());
        assertEquals("my-key", certSigner.getKvKeyName());
        assertEquals("v1", certSigner.getKvKeyVersion());
    }

    /**
     * Tests that missing required options (such as Key Vault details) triggers a {@link MissingParameterException}.
     */
    @Test
    void testMissingRequiredOptionThrowsException() {
        String[] args = {
            "--output-cert-path", "cert.pem",
            "--cert-csr-path", "csr.pem"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        assertThrows(MissingParameterException.class, () -> cmd.parseArgs(args));
    }

    /**
     * Tests that unknown CLI arguments trigger an {@link UnmatchedArgumentException}.
     */
    @Test
    void testUnknownOptionThrowsException() {
        String[] args = {
            "--output-cert-path", "cert.pem",
            "--cert-csr-path", "csr.pem",
            "--kv-name", "my-vault",
            "--kv-key-name", "my-key",
            "--kv-key-version", "v1",
            "--unknown-arg", "value"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        assertThrows(UnmatchedArgumentException.class, () -> cmd.parseArgs(args));
    }

    /**
     * Tests that running the launcher without either CSR or Subject DN triggers a {@link ParameterException}.
     */
    @Test
    void testCallWithoutCsrOrSubjectThrowsException() {
        String[] args = {
            "--output-cert-path", "cert.pem",
            "--kv-name", "my-vault",
            "--kv-key-name", "my-key",
            "--kv-key-version", "v1"
        };

        CertSignerLauncher launcher = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(launcher);
        cmd.parseArgs(args);

        assertThrows(ParameterException.class, launcher::call);
    }

    /**
     * Tests that providing Subject DN without public key triggers a {@link ParameterException}.
     */
    @Test
    void testCallWithSubjectDnWithoutPublicKeyThrowsException() {
        String[] args = {
            "--output-cert-path", "cert.pem",
            "--cert-subject-dn", "CN=example.com",
            "--kv-name", "my-vault",
            "--kv-key-name", "my-key",
            "--kv-key-version", "v1"
        };

        CertSignerLauncher launcher = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(launcher);
        cmd.parseArgs(args);

        assertThrows(ParameterException.class, launcher::call);
    }
}
