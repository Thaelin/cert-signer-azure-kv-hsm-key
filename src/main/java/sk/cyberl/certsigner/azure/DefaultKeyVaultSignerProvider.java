package sk.cyberl.certsigner.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.KeyCurveName;
import com.azure.security.keyvault.keys.models.KeyType;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link KeyVaultSignerProvider} that connects to Azure Key Vault,
 * retrieves the HSM key metadata, and prepares an {@link AzureKeyVaultContentSigner}.
 */
public class DefaultKeyVaultSignerProvider implements KeyVaultSignerProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultKeyVaultSignerProvider.class);

    private final TokenCredential credential;

    /**
     * Constructs a new {@code DefaultKeyVaultSignerProvider} using default Azure authentication credentials.
     */
    public DefaultKeyVaultSignerProvider() {
        this(new DefaultAzureCredentialBuilder().build());
    }

    /**
     * Constructs a new {@code DefaultKeyVaultSignerProvider} with a custom {@link TokenCredential}.
     *
     * @param credential The Azure token credential to use for authentication.
     */
    public DefaultKeyVaultSignerProvider(TokenCredential credential) {
        this.credential = credential;
    }

    /**
     * Creates a {@link ContentSigner} for the specified Azure Key Vault key by retrieving
     * the key metadata, determining the appropriate signature algorithm, and initializing
     * a cryptography client.
     *
     * @param kvName       Key Vault name or full vault URL.
     * @param kvKeyName    Name of the key stored in Azure Key Vault.
     * @param kvKeyVersion Optional version of the key. If null or blank, the latest version is used.
     * @return A configured {@link ContentSigner} backed by Azure Key Vault.
     * @throws IllegalStateException if the key cannot be found in Azure Key Vault.
     */
    @Override
    public ContentSigner createContentSigner(String kvName, String kvKeyName, String kvKeyVersion) {
        String vaultUrl = formatVaultUrl(kvName);
        LOGGER.info("Connecting to Azure Key Vault: {}", vaultUrl);

        KeyClient keyClient = new KeyClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(credential)
                .buildClient();

        KeyVaultKey key = (kvKeyVersion != null && !kvKeyVersion.isBlank())
                ? keyClient.getKey(kvKeyName, kvKeyVersion)
                : keyClient.getKey(kvKeyName);

        if (key == null) {
            throw new IllegalStateException("Could not retrieve key from Key Vault: " + kvKeyName);
        }

        KeyType keyType = key.getKeyType();
        SignatureAlgorithm signatureAlgorithm;
        String algorithmName;
        boolean isEc;

        if (KeyType.EC.equals(keyType) || KeyType.EC_HSM.equals(keyType)) {
            isEc = true;
            KeyCurveName curve = key.getKey() != null ? key.getKey().getCurveName() : null;

            if (KeyCurveName.P_384.equals(curve)) {
                signatureAlgorithm = SignatureAlgorithm.ES384;
                algorithmName = "SHA384withECDSA";
            } else if (KeyCurveName.P_521.equals(curve)) {
                signatureAlgorithm = SignatureAlgorithm.ES512;
                algorithmName = "SHA512withECDSA";
            } else if (KeyCurveName.P_256K.equals(curve)) {
                signatureAlgorithm = SignatureAlgorithm.ES256K;
                algorithmName = "SHA256withECDSA";
            } else {
                signatureAlgorithm = SignatureAlgorithm.ES256;
                algorithmName = "SHA256withECDSA";
            }
        } else {
            // Default to RSA / RSA_HSM
            isEc = false;
            signatureAlgorithm = SignatureAlgorithm.RS256;
            algorithmName = "SHA256withRSA";
        }

        LOGGER.info("Retrieved Key Vault key '{}' (Type: {}, Signature Algorithm: {})",
                kvKeyName, keyType, algorithmName);

        AlgorithmIdentifier algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName);

        CryptographyClient cryptoClient = new CryptographyClientBuilder()
                .keyIdentifier(key.getId())
                .credential(credential)
                .buildClient();

        return new AzureKeyVaultContentSigner(cryptoClient, signatureAlgorithm, algorithmIdentifier, isEc);
    }

    /**
     * Normalizes and formats the Azure Key Vault URL.
     *
     * @param kvName Vault name or URL.
     * @return Fully qualified Key Vault HTTPS URL.
     */
    private String formatVaultUrl(String kvName) {
        if (kvName.startsWith("https://") || kvName.startsWith("http://")) {
            return kvName;
        }
        return String.format("https://%s.vault.azure.net", kvName.trim());
    }
}
