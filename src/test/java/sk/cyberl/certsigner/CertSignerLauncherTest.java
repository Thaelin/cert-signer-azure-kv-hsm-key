package sk.cyberl.certsigner;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import picocli.CommandLine.MissingParameterException;
import picocli.CommandLine.UnmatchedArgumentException;

import static org.junit.jupiter.api.Assertions.*;

class CertSignerLauncherTest {

    @Test
    void testParseValidArguments() {
        String[] args = {
            "--signing-cert-path", "cert.pem",
            "--cert-csr-path", "csr.pem",
            "--kv-name", "my-vault",
            "--kv-key-name", "my-key",
            "--kv-key-version", "v1"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        cmd.parseArgs(args);

        assertEquals("cert.pem", certSigner.getSigningCertPath());
        assertEquals("csr.pem", certSigner.getCertCsrPath());
        assertEquals("my-vault", certSigner.getKvName());
        assertEquals("my-key", certSigner.getKvKeyName());
        assertEquals("v1", certSigner.getKvKeyVersion());
    }

    @Test
    void testParseWithEqualsSyntax() {
        String[] args = {
            "--signing-cert-path=cert.pem",
            "--cert-csr-path=csr.pem",
            "--kv-name=my-vault",
            "--kv-key-name=my-key",
            "--kv-key-version=v1"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        cmd.parseArgs(args);

        assertEquals("cert.pem", certSigner.getSigningCertPath());
        assertEquals("csr.pem", certSigner.getCertCsrPath());
        assertEquals("my-vault", certSigner.getKvName());
        assertEquals("my-key", certSigner.getKvKeyName());
        assertEquals("v1", certSigner.getKvKeyVersion());
    }

    @Test
    void testParseWithShortOptions() {
        String[] args = {
            "-c", "cert.pem",
            "-r", "csr.pem",
            "-v", "my-vault",
            "-k", "my-key",
            "-e", "v1"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        cmd.parseArgs(args);

        assertEquals("cert.pem", certSigner.getSigningCertPath());
        assertEquals("csr.pem", certSigner.getCertCsrPath());
        assertEquals("my-vault", certSigner.getKvName());
        assertEquals("my-key", certSigner.getKvKeyName());
        assertEquals("v1", certSigner.getKvKeyVersion());
    }

    @Test
    void testExecuteReturnsZeroOnValidArguments() {
        String[] args = {
            "--signing-cert-path", "cert.pem",
            "--cert-csr-path", "csr.pem",
            "--kv-name", "my-vault",
            "--kv-key-name", "my-key",
            "--kv-key-version", "v1"
        };

        int exitCode = new CommandLine(new CertSignerLauncher()).execute(args);
        assertEquals(CommandLine.ExitCode.OK, exitCode);
    }

    @Test
    void testMissingRequiredOptionThrowsException() {
        String[] args = {
            "--signing-cert-path", "cert.pem",
            "--cert-csr-path", "csr.pem"
        };

        CertSignerLauncher certSigner = new CertSignerLauncher();
        CommandLine cmd = new CommandLine(certSigner);
        assertThrows(MissingParameterException.class, () -> cmd.parseArgs(args));
    }

    @Test
    void testUnknownOptionThrowsException() {
        String[] args = {
            "--signing-cert-path", "cert.pem",
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
}
