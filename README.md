# Certificate signer using Azure Key Vault (premium tier) HSM key

[![GitHub Release](https://img.shields.io/github/v/release/Thaelin/cert-signer-azure-kv-hsm-key?style=flat-square&logo=github&color=0078D4)](https://github.com/Thaelin/cert-signer-azure-kv-hsm-key/releases/latest)
[![Release Status](https://img.shields.io/github/actions/workflow/status/Thaelin/cert-signer-azure-kv-hsm-key/release.yml?style=flat-square&logo=githubactions&logoColor=white&label=Release)](https://github.com/Thaelin/cert-signer-azure-kv-hsm-key/actions/workflows/release.yml)
[![Java 25+](https://img.shields.io/badge/Java-25+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://adoptium.net/)
[![Azure Key Vault](https://img.shields.io/badge/Azure_Key_Vault-HSM_Signing-0078D4?style=flat-square&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/en-us/products/key-vault/)
[![License](https://img.shields.io/badge/License-Apache_2.0-2ea44f?style=flat-square&logo=apache)](LICENSE)

A CLI tool to create and sign X.509 v3 digital certificates using non-exportable Azure Key Vault HSM keys (RSA or ECDSA) based on a CSR or a standalone public key.

Standard OpenSSL APIs and traditional cryptographic tooling require local access to the private key. Because Azure Key Vault HSM keys are non-exportable by design, this tool delegates certificate signing directly to Azure Key Vault's cryptographic signing API.

---

## Features

- **Azure Key Vault HSM Signing**: Signs X.509 v3 certificates using non-exportable RSA or ECDSA (P-256, P-384, P-521, P-256K) keys in Azure Key Vault.
- **Flexible Input Modes**:
  - **CSR Mode**: Sign certificates directly from a PKCS#10 Certificate Signing Request (CSR).
  - **Direct Mode**: Sign certificates using Subject Distinguished Name (DN) and a standalone public key file.
- **Multiple Encodings**: Supports input and output in both **PEM** and binary **DER** formats. Output format is automatically determined based on the file extension (`.der` produces DER; other extensions produce PEM).
- **Custom Attributes & Extensions**: Support for ASN.1 DER certificate attributes and extension requests (via file or Base64 string).
- **Provenance & Extension Logging**: Automatically logs every certificate attribute and decoded X.509 extension (e.g. Basic Constraints, Key Usage, SAN, AKI/SKI, AIA, Policies) with explicit origin tracking (`[CSR]`, `[CLI]`, `[DEFAULT]`, `[KEY_VAULT]`).
- **Configurable Validity**: Customize validity duration in days (default: 365).
- **Seamless Authentication**: Integrates with `DefaultAzureCredential` (Azure CLI, Managed Identity, Service Principals, etc.).

---

## 🚀 User Guide (Quick Start)

> **Note:** You do **not** need Maven, Git, or any build tools to use this application. Simply download the prebuilt JAR from Releases.

### 1. Prerequisites (for Users)
- **Java**: Java 25 or higher (JRE or JDK, e.g. [Eclipse Temurin](https://adoptium.net/)).
- **Azure Permissions**: Azure credentials configured with permissions to sign using Azure Key Vault (`Key Vault Crypto User` role or `sign` key permission).
  - *Easiest setup:* Run `az login` via the [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli).

### 2. Download Prebuilt JAR
Download the latest executable JAR (`cert-signer-azure-kv-hsm-key.jar`) from the **[GitHub Releases](https://github.com/Thaelin/cert-signer-azure-kv-hsm-key/releases/latest)** page.

### 3. Run
Run the downloaded JAR directly:

```bash
java -jar cert-signer-azure-kv-hsm-key.jar [OPTIONS]
```

---

## 📖 Usage Examples

### 1. Sign using a CSR (PEM output)

```bash
java -jar cert-signer-azure-kv-hsm-key.jar \
  --output-cert-path cert.pem \
  --cert-csr-path request.csr \
  --validity-days 365 \
  --kv-name my-keyvault \
  --kv-key-name my-ca-key \
  --kv-key-version 7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
```

### 2. Sign using Subject DN and Public Key (DER output)

```bash
java -jar cert-signer-azure-kv-hsm-key.jar \
  -o cert.der \
  -s "CN=example.com,O=My Org,C=US" \
  -p public_key.pem \
  -d 730 \
  -v my-keyvault \
  -k my-ca-key \
  -e 7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
```

### 3. Sign with ASN.1 DER Attributes / Extensions

```bash
java -jar cert-signer-azure-kv-hsm-key.jar \
  --output-cert-path cert.pem \
  --cert-subject-dn "CN=example.com,O=My Org,C=US" \
  --cert-public-key-path public_key.pem \
  --cert-attributes extensions.der \
  --kv-name my-keyvault \
  --kv-key-name my-ca-key \
  --kv-key-version 7a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
```

---

## ⚙️ CLI Reference & Parameters

| Option | Long Option | Parameter | Required | Default | Description |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `-o` | `--output-cert-path` | `<path>` | **Yes** | — | Path to write the output certificate file. Uses DER encoding if filename ends with `.der`, otherwise PEM encoding. |
| `-r` | `--cert-csr-path` | `<path>` | **Conditional** | — | Path to PKCS#10 Certificate Signing Request (CSR) file (PEM or DER format). Required if `-s` is not specified. |
| `-s` | `--cert-subject-dn` | `<dn>` | **Conditional** | — | Certificate Subject Distinguished Name (e.g. `'CN=example.com,O=Org,C=US'`). Required if `-r` is not specified. |
| `-p` | `--cert-public-key-path` | `<path>` | **Conditional** | — | Path to subject public key file (PEM or DER format). Required when `-s` is specified. |
| `-a` | `--cert-attributes` | `<attributes>` | No | — | Path to an ASN.1 DER attributes file or a Base64-encoded ASN.1 string containing certificate attributes/extensions. |
| `-d` | `--validity-days`, `--validity-period` | `<days>` | No | `365` | Certificate validity period in days. |
| `-v` | `--kv-name` | `<name>` | **Yes** | — | Azure Key Vault name or full vault URL (e.g. `my-vault` or `https://my-vault.vault.azure.net`). |
| `-k` | `--kv-key-name` | `<name>` | **Yes** | — | Name of the signing key in Azure Key Vault. |
| `-e` | `--kv-key-version` | `<version>` | **Yes** | — | Key version identifier in Azure Key Vault. |
| `-h` | `--help` | — | No | — | Display help message and exit. |
| `-V` | `--version` | — | No | — | Display version information and exit. |

> **Input Modes:**
> - **CSR Mode:** Supply `--cert-csr-path` (`-r`).
> - **Direct Mode:** Supply both `--cert-subject-dn` (`-s`) and `--cert-public-key-path` (`-p`).

---

## 🔐 Azure Authentication

Authentication to Azure Key Vault is handled automatically via Azure Identity (`DefaultAzureCredential`). It checks for credentials in the following order:

1. **Azure CLI**: Run `az login` prior to executing the tool (recommended for local user workflows).
2. **Environment Variables**: Set credentials (recommended for automated/CI environments):
   - `AZURE_CLIENT_ID`
   - `AZURE_CLIENT_SECRET`
   - `AZURE_TENANT_ID`
3. **Managed Identity / Workload Identity**: Automatically used when running on Azure VMs, App Services, Container Apps, or Azure Kubernetes Service (AKS).
4. **Developer Tools**: Credentials from Azure Developer CLI (`azd`) or IDE sessions.

---

## 🛠️ Developer Guide (Building from Source)

If you are a developer looking to build, customize, or contribute to the codebase:

### Prerequisites (Developers)
- **Java JDK**: Java Development Kit 25 or higher
- **Maven**: Apache Maven 3.8+
- **Git**

### Building the Project

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Thaelin/cert-signer-azure-kv-hsm-key.git
   cd cert-signer-azure-kv-hsm-key
   ```

2. **Build the shaded JAR:**
   ```bash
   mvn clean package
   ```

3. The executable shaded JAR will be generated in the `target/` folder:
   ```bash
   target/cert-signer-azure-kv-hsm-key.jar
   ```

### Running Tests
Execute unit and integration test suites:
```bash
mvn test
```

---

## License

This project is licensed under the [Apache-2.0 License](LICENSE).
