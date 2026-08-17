package sk.cyberl.certsigner.azure;

import org.bouncycastle.operator.ContentSigner;

/**
 * Provider interface responsible for creating a Bouncy Castle {@link ContentSigner}
 * backed by Azure Key Vault HSM keys.
 */
public interface KeyVaultSignerProvider {

    /**
     * Creates a {@link ContentSigner} for the specified Azure Key Vault key.
     *
     * @param kvName Key Vault name or URL
     * @param kvKeyName Key name in Key Vault
     * @param kvKeyVersion Key version in Key Vault
     * @return a configured {@link ContentSigner}
     */
    ContentSigner createContentSigner(String kvName, String kvKeyName, String kvKeyVersion);
}
