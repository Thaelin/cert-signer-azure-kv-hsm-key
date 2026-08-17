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

/**
 * Default implementation of {@link KeyVaultSignerProvider} that connects to Azure Key Vault,
 * retrieves the HSM key metadata, and prepares an {@link AzureKeyVaultContentSigner}.
 */
public class DefaultKeyVaultSignerProvider implements KeyVaultSignerProvider {

    private final TokenCredential credential;

    public DefaultKeyVaultSignerProvider() {
        this(new DefaultAzureCredentialBuilder().build());
    }

    public DefaultKeyVaultSignerProvider(TokenCredential credential) {
        this.credential = credential;
    }

    @Override
    public ContentSigner createContentSigner(String kvName, String kvKeyName, String kvKeyVersion) {
        String vaultUrl = formatVaultUrl(kvName);

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

        AlgorithmIdentifier algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmName);

        CryptographyClient cryptoClient = new CryptographyClientBuilder()
                .keyIdentifier(key.getId())
                .credential(credential)
                .buildClient();

        return new AzureKeyVaultContentSigner(cryptoClient, signatureAlgorithm, algorithmIdentifier, isEc);
    }

    private String formatVaultUrl(String kvName) {
        if (kvName.startsWith("https://") || kvName.startsWith("http://")) {
            return kvName;
        }
        return String.format("https://%s.vault.azure.net", kvName.trim());
    }
}
