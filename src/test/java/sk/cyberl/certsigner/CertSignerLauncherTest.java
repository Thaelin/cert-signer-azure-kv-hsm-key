package sk.cyberl.certsigner;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import picocli.CommandLine.MissingParameterException;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.UnmatchedArgumentException;

import static org.junit.jupiter.api.Assertions.*;

class CertSignerLauncherTest {

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
