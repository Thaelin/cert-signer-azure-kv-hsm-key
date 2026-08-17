# cert-signer-azure-kv-hsm-key

Program that can be used to create digital certificate based on CSR (or without) using Azure Key Vault premium HSM keys (non-exportable). Standard OpenSSL APIs expect signing key to be present in the environment but in case of HSM keys they are by nature non-exportable so dedicated cloud vendors key signing API needs to be used.

## Features

- **Azure Key Vault HSM Signing**: Signs X.509 v3 certificates using non-exportable RSA or ECDSA (P-256, P-384, P-521, P-256K) keys in Azure Key Vault.
- **Flexible Input Modes**:
  - **CSR Mode**: Sign certificates directly from a PKCS#10 Certificate Signing Request (CSR).
  - **Direct Mode**: Sign certificates using Subject Distinguished Name (DN) and a standalone public key file.
- **Multiple Encodings**: Supports input and output in both **PEM** and binary **DER** formats. Output format is automatically determined based on the file extension (`.der` produces DER; other extensions produce PEM).
- **Custom Attributes & Extensions**: Support for ASN.1 DER certificate attributes and extension requests (via file or Base64 string).
- **Configurable Validity**: Customize validity duration in days.

---

## Prerequisites

- **Java**: Java 25 or higher
- **Maven**: Maven 3.8+ (for building)
- **Azure Authentication**: Azure credentials configured for [DefaultAzureCredential](https://learn.microsoft.com/en-us/java/api/com.azure.identity.defaultazurecredential) (e.g. `az login`, environment variables `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`, or Managed Identity) with permissions to sign using Azure Key Vault (`Key Vault Crypto User` or `sign` key permission).

---

## Build

Build the runnable shaded JAR using Maven:

```bash
mvn clean package
```

The resulting executable JAR will be generated in the `target/` directory:
`target/cert-signer-azure-kv-hsm-key.jar`

---

## Usage

Run the JAR using the `java -jar` command:

```bash
java -jar target/cert-signer-azure-kv-hsm-key.jar [OPTIONS]
```

### Examples

#### 1. Sign using a CSR (PEM output)

```bash
java -jar target/cert-signer-azure-kv-hsm-key.jar \
  --output-cert-path cert.pem \
  --cert-csr-path request.csr \
  --validity-days 365 \
  --kv-name my-keyvault \
  --kv-key-name my-ca-key \
  --kv-key-version 7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
```

#### 2. Sign using Subject DN and Public Key (DER output)

```bash
java -jar target/cert-signer-azure-kv-hsm-key.jar \
  -o cert.der \
  -s "CN=example.com,O=My Org,C=US" \
  -p public_key.pem \
  -d 730 \
  -v my-keyvault \
  -k my-ca-key \
  -e 7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
```

#### 3. Sign with ASN.1 DER Attributes / Extensions

```bash
java -jar target/cert-signer-azure-kv-hsm-key.jar \
  --output-cert-path cert.pem \
  --cert-subject-dn "CN=example.com,O=My Org,C=US" \
  --cert-public-key-path public_key.pem \
  --cert-attributes extensions.der \
  --kv-name my-keyvault \
  --kv-key-name my-ca-key \
  --kv-key-version 7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
```

---

## Parameters

| Option | Long Option | Parameter | Required | Default | Description |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `-o` | `--output-cert-path` | `<path>` | **Yes** | — | Path to write the output certificate file. Uses DER encoding if filename ends with `.der`, otherwise PEM encoding. |
| `-r` | `--cert-csr-path` | `<path>` | **Conditional** | — | Path to the PKCS#10 Certificate Signing Request (CSR) file (PEM or DER format). Required if `-s` is not specified. |
| `-s` | `--cert-subject-dn` | `<dn>` | **Conditional** | — | Certificate Subject Distinguished Name (e.g. `'CN=example.com,O=Org,C=US'`). Required if `-r` is not specified. |
| `-p` | `--cert-public-key-path` | `<path>` | **Conditional** | — | Path to the subject's public key file (PEM or DER format). Required when `-s` is specified. |
| `-a` | `--cert-attributes` | `<attributes>` | No | — | Path to an ASN.1 DER attributes file or a Base64-encoded ASN.1 string containing certificate attributes/extensions. |
| `-d` | `--validity-days`, `--validity-period` | `<days>` | No | `365` | Certificate validity period in days. |
| `-v` | `--kv-name` | `<name>` | **Yes** | — | Azure Key Vault name or full vault URL (e.g. `my-vault` or `https://my-vault.vault.azure.net`). |
| `-k` | `--kv-key-name` | `<name>` | **Yes** | — | Name of the signing key in Azure Key Vault. |
| `-e` | `--kv-key-version` | `<version>` | **Yes** | — | Key version identifier in Azure Key Vault. |
| `-h` | `--help` | — | No | — | Display the help message and exit. |
| `-V` | `--version` | — | No | — | Display version information and exit. |

> **Note on Input Modes:**
> You must provide either:
> 1. `--cert-csr-path` (`-r`) for CSR-based certificate creation, OR
> 2. Both `--cert-subject-dn` (`-s`) and `--cert-public-key-path` (`-p`) for direct certificate creation.

---

## Authentication

Authentication to Azure Key Vault is handled transparently via Azure Identity (`DefaultAzureCredential`). It attempts authentication in the following order:

1. **Environment Variables**:
   - `AZURE_CLIENT_ID`
   - `AZURE_CLIENT_SECRET`
   - `AZURE_TENANT_ID`
2. **Workload Identity / Managed Identity**: Enabled on Azure VMs, App Services, or Azure Kubernetes Service (AKS).
3. **Azure CLI**: Run `az login` prior to executing the tool.
4. **Azure Developer CLI / IDE Credentials**: Authenticated sessions via Azure CLI or Azure Developer CLI (`azd`).

---

## License

This project is licensed under the [Apache-2.0 License](LICENSE).
