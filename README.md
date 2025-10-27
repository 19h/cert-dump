<h1 align="center">cert-dump</h1>

<h5 align="center">High-performance X.509 certificate scanner and extractor for binary files.</h5>

<div align="center">
  <a href="https://crates.io/crates/cert-dump">
    crates.io
  </a>
  —
  <a href="https://github.com/19h/cert-dump">
    Github
  </a>
</div>

<br />

`cert-dump` is a command-line utility for scanning binary files and directories to find embedded X.509 certificates. It supports both DER (Distinguished Encoding Rules) and PEM (Privacy-Enhanced Mail) formats, providing detailed certificate information, optional extraction capabilities, and intelligent duplicate detection across multiple files.

### Installation

```shell
cargo install cert-dump
```

### Usage Examples

**1. Basic Scan (List Only)**  
Scans a binary file and displays all certificates found, without extraction.

```shell
cert-dump firmware.bin
```

**2. Extract All Certificates (DER + PEM)**  
Extracts certificates to the `cert_dump/` directory in both DER and PEM formats.

```shell
cert-dump firmware.bin --dump
```

**3. Extract DER Format Only**  
Extracts only DER-encoded certificates.

```shell
cert-dump firmware.bin --dump --der
```

**4. Extract PEM Format Only**  
Extracts only PEM-encoded certificates.

```shell
cert-dump firmware.bin --dump --pem
```

**5. Verbose Output with Custom Directory**  
Scans with verbose logging and extracts to a custom output directory.

```shell
cert-dump firmware.bin -v --dump -o my_certs
```

**6. Force Overwrite**  
Overwrites existing files in the output directory.

```shell
cert-dump firmware.bin --dump --force
```

**7. Recursive Directory Scan**  
Recursively scans all files in a directory for certificates.

```shell
cert-dump -R /path/to/directory
```

**8. Recursive Scan with Extension Filter**  
Scans only specific file types (e.g., executables, JARs, or certificate files).

```shell
cert-dump -R --ext exe,dll,jar,apk,pem,der,crt /path/to/directory
```

**9. Duplicate Detection with Annotation**  
Finds all certificates but marks duplicates with references to first occurrence.

```shell
cert-dump -R --mark-duplicates /path/to/directory
```

**10. Unique Certificates Only**  
Shows only the first occurrence of each unique certificate (suppresses duplicates).

```shell
cert-dump -R --unique-only /path/to/directory
```

**11. Parallel Scanning with Custom Threads**  
Scans multiple files in parallel for faster processing.

```shell
cert-dump -R --threads 8 /large/directory
```

**12. Scan with Symlink Following and Depth Limit**  
Follows symbolic links and limits recursion depth.

```shell
cert-dump -R --follow-symlinks --max-depth 3 /path/to/directory
```

**13. JSON Output for Automated Processing**  
Outputs results as newline-delimited JSON with duplicate information.

```shell
cert-dump -R --json /path/to/directory > results.jsonl
```

**14. SQLite Database Export**  
Writes all certificates and occurrences to a SQLite database for analysis.

```shell
cert-dump -R --sqlite certs.db /path/to/directory
```

**15. Combined JSON and SQLite Output**  
Outputs JSON to stdout while simultaneously writing to SQLite.

```shell
cert-dump -R --json --sqlite certs.db /path/to/directory
```

**16. Query SQLite Results**  
Example queries for the SQLite database.

```shell
# Find all unique certificates
sqlite3 certs.db "SELECT sha256, subject, occurrence_count FROM certificate;"

# Find all occurrences of a specific certificate
sqlite3 certs.db "SELECT path, offset FROM occurrence WHERE sha256='...';"  

# Find certificates in a specific file
sqlite3 certs.db "SELECT DISTINCT c.* FROM certificate c JOIN occurrence o ON c.sha256=o.sha256 WHERE o.path LIKE '%filename%';"
```

**17. Certificate Chain Visualization**  
Display certificates in a tree format showing parent-child signing relationships.

```shell
cert-dump -R --tree /path/to/directory
```

**18. Filter and Visualize Certificate Chains**  
Combine filtering with tree visualization to focus on specific certificate types.

```shell
# Show only RSA certificates and their relationships
cert-dump -R --tree --key-algo rsa /path/to/certs

# Visualize only valid certificates
cert-dump -R --tree --valid /path/to/certs
```

**19. Certificate Filtering**  
Filter certificates by various fields with fuzzy matching and multiple criteria.

```shell
# Find all Apple certificates
cert-dump -R --org Apple /System/Library/Keychains

# Find expired RSA certificates
cert-dump -R --expired --key-algo rsa /path/to/certs

# Find certificates from Apple OR Google with EC keys
cert-dump -R --org Apple --org Google --key-algo ec /path

# Find weak certificates (SHA-1 or small key sizes)
cert-dump -R --sig-algo sha1 /path
cert-dump -R --key-algo rsa --key-size 1024 /path
```

### Features

*   **Fast Binary Scanning:** Uses optimized pattern matching (`memchr`) to efficiently scan large binaries for both DER and PEM certificate formats.
*   **Dual Format Support:** Detects certificates in both DER (raw binary ASN.1) and PEM (Base64-encoded) formats.
*   **Recursive Directory Scanning:** Scan entire directory trees with configurable depth limits and extension filters.
*   **Parallel Processing:** Multi-threaded file scanning for high-performance analysis of large directory trees.
*   **Intelligent Duplicate Detection:** 
    *   SHA-256 fingerprinting to identify duplicate certificates across files
    *   `--unique-only` mode to suppress duplicate output
    *   `--mark-duplicates` mode to annotate duplicates with first-occurrence references
    *   On-the-fly deduplication with occurrence counting
*   **Detailed Certificate Metadata:** Displays comprehensive information including:
    *   Subject and Issuer Distinguished Names (DN)
    *   Serial number
    *   SHA-256 fingerprint
    *   Validity period (Not Before/Not After dates)
    *   Public key algorithm and size (RSA, EC, Ed25519, Ed448)
    *   Signature algorithm
    *   File path, offset and size
*   **Advanced Filtering:**
    *   **File-level:** Extension-based filtering, maximum file size limits, hard link detection, symlink traversal control
    *   **Certificate-level:** Filter by organization, common name, country, locality, state, organizational unit
    *   **Identifier-based:** Filter by serial number, SHA-256 fingerprint, full subject/issuer DN
    *   **Algorithm-based:** Filter by public key algorithm (RSA, EC, Ed25519, DSA, PQC) and signature algorithm (SHA-1, SHA-256, ECDSA, etc.)
    *   **Key size:** Filter by public key bit length (e.g., 2048, 4096)
    *   **Validity:** Filter by expiration status (--expired, --valid)
    *   **Fuzzy matching:** Case-insensitive substring search with smart algorithm variant matching
    *   **Multiple values:** Specify filters multiple times for OR logic; different filters use AND logic
    *   **Performance:** Filtering happens during scanning with no post-processing overhead
*   **Multiple Output Formats:**
    *   **Text:** Human-readable colored terminal output with proper formatting
    *   **Tree:** Hierarchical visualization of certificate signing relationships
    *   **JSON:** Newline-delimited JSON with full certificate metadata and duplicate tracking
    *   **SQLite:** Relational database with `certificate` and `occurrence` tables for complex queries
    *   Can combine formats (e.g., `--json --sqlite` for both outputs simultaneously)
*   **Certificate Relationship Visualization:**
    *   Tree view showing parent-child signing relationships
    *   Automatic root certificate detection (self-signed)
    *   Nested display of certificate chains
    *   Compatible with all filtering options
*   **Flexible Extraction:** Extract certificates in DER format, PEM format, or both (default).
*   **Verbose Mode:** Additional details including DER lengths, PEM block offsets, worker thread status, and parse diagnostics.

### Technical Background

#### X.509 Certificates

X.509 is a standard for public key certificates used in TLS/SSL, code signing, and other cryptographic protocols. Certificates bind a public key to an identity and are signed by a Certificate Authority (CA) to establish trust.

#### DER Encoding (Distinguished Encoding Rules)

DER is a binary encoding format based on ASN.1 (Abstract Syntax Notation One). It provides a canonical way to serialize structured data. X.509 certificates are typically stored and transmitted in DER format.

**Structure:**  
A DER-encoded certificate begins with a SEQUENCE tag (`0x30`) followed by a length encoding. This tool scans for these patterns and validates them using full X.509 parsing to minimize false positives.

**Detection Method:**  
1. Scan for byte `0x30` (SEQUENCE tag)
2. Parse DER length encoding (supports both short and long forms)
3. Validate the candidate as a proper X.509 certificate using `x509-parser`

#### PEM Encoding (Privacy-Enhanced Mail)

PEM is a Base64-encoded representation of DER data, wrapped with human-readable headers and footers:

```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG...
-----END CERTIFICATE-----
```

**Detection Method:**  
1. Search for `-----BEGIN CERTIFICATE-----` markers
2. Find matching `-----END CERTIFICATE-----` markers
3. Extract and decode the Base64 content between markers
4. Validate the decoded DER certificate

#### Public Key Algorithms

This tool recognizes and displays key information for a comprehensive set of cryptographic algorithms:

**RSA Variants:**
*   **RSA:** Standard RSA encryption and signatures (extracts modulus bit length: 1024, 2048, 4096, 8192+ bits)
*   **RSA-PSS:** Probabilistic Signature Scheme
*   **RSA-OAEP:** Optimal Asymmetric Encryption Padding

**DSA:**
*   **DSA:** Digital Signature Algorithm with SHA-1, SHA-224, SHA-256

**Elliptic Curve Cryptography:**
*   **NIST/ANSI Curves:** P-192, P-224, P-256, P-384, P-521 (secp curves)
*   **SECG Curves:** secp256k1 (Bitcoin curve)
*   **Brainpool Curves:** brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
*   **Modern Curves:** X25519, X448 (ECDH), Ed25519, Ed448 (EdDSA)

**Chinese National Standards:**
*   **SM2:** Chinese elliptic curve public key algorithm (256-bit)
*   **SM3:** Chinese hash algorithm

**Russian GOST Standards:**
*   **GOST R 34.10-2012:** Russian elliptic curve signature algorithm (256-bit and 512-bit variants)
*   **Streebog (GOST R 34.11-2012):** Modern Russian hash function

**Post-Quantum Cryptography (NIST PQC):**
*   **ML-KEM (CRYSTALS-Kyber):** Key Encapsulation Mechanism (512, 768, 1024-bit security levels)
*   **ML-DSA (CRYSTALS-Dilithium):** Digital signature algorithm (44, 65, 87 parameter sets)
*   **Provisional Round 3 OIDs:** Support for experimental PQC implementations

**Signature Algorithms Recognized:**
*   RSA with MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
*   ECDSA with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
*   EdDSA (Ed25519, Ed448)
*   SM2 with SM3
*   GOST R 34.10-2012 with Streebog
*   ML-DSA (Post-Quantum signatures)

### Output File Structure

When run with `--dump`, `cert-dump` creates files in the specified output directory:

*   `cert.0.der`, `cert.0.pem`: First certificate (both formats by default)
*   `cert.1.der`, `cert.1.pem`: Second certificate
*   ...and so on

Use `--der` or `--pem` flags to restrict output to a single format.

### Certificate Filtering

`cert-dump` supports comprehensive certificate filtering based on various fields. All filters use **fuzzy matching** (case-insensitive, substring search) and can be specified multiple times for OR logic.

#### Filter Categories

**Distinguished Name (DN) Fields:**

| Flag | Description | Example |
|------|-------------|---------|
| `--org <ORG>` | Organization (O) | `--org Apple --org Microsoft` |
| `--ou <OU>` | Organizational Unit (OU) | `--ou Engineering` |
| `--common <COMMON>` | Common Name (CN) | `--common "*.apple.com"` |
| `--country <COUNTRY>` | Country (C) | `--country US --country GB` |
| `--locality <LOCALITY>` | Locality (L) | `--locality "San Francisco"` |
| `--state <STATE>` | State/Province (ST) | `--state California` |
| `--subject <TEXT>` | Full Subject DN | `--subject "Apple Inc"` |
| `--issuer <TEXT>` | Full Issuer DN | `--issuer "DigiCert"` |

**Certificate Identifiers:**

| Flag | Description | Example |
|------|-------------|---------|
| `--serial <SERIAL>` | Serial number (hex substring) | `--serial 1A2B3C` |
| `--sha256 <HASH>` | SHA-256 fingerprint (substring) | `--sha256 da98f640` |

**Cryptographic Algorithms:**

| Flag | Description | Example |
|------|-------------|---------|
| `--key-algo <ALGO>` | Public key algorithm | `--key-algo rsa`, `--key-algo ec` |
| `--sig-algo <ALGO>` | Signature algorithm | `--sig-algo sha256`, `--sig-algo ecdsa` |
| `--key-size <BITS>` | Public key size in bits | `--key-size 2048 --key-size 4096` |

**Validity Period:**

| Flag | Description |
|------|-------------|
| `--expired` | Show only expired certificates |
| `--valid` | Show only currently valid certificates |

#### Smart Algorithm Matching

**Public Key Algorithm (`--key-algo`):**
- `rsa` → Any RSA variant
- `rsa-pss`, `pss` → RSA-PSS specifically
- `ec`, `ecc` → Any elliptic curve
- `ecdsa` → ECDSA specifically
- `ed25519`, `ed448`, `eddsa` → EdDSA algorithms
- `dilithium`, `ml-dsa` → Post-quantum Dilithium/ML-DSA
- `kyber`, `ml-kem` → Post-quantum Kyber/ML-KEM
- `sm2` → Chinese SM2
- `gost` → Russian GOST

**Signature Algorithm (`--sig-algo`):**
- `sha` → Any SHA-based signature
- `sha1`, `sha-1` → SHA-1 specifically
- `sha2` → SHA-256, SHA-384, or SHA-512
- `sha256`, `sha-256` → SHA-256 specifically
- `rsa` → Any RSA signature
- `ecdsa` → ECDSA signatures
- `md5` → MD5 signatures (deprecated)

#### Filter Logic

**Multiple Values (OR):** Same flag multiple times creates OR condition
```bash
# Find certificates from Apple OR Microsoft
cert-dump -R --org Apple --org Microsoft /path
```

**Multiple Flags (AND):** Different flags create AND condition
```bash
# Find Apple certificates with EC keys
cert-dump -R --org Apple --key-algo ec /path
```

**Complex Filtering:**
```bash
# Find certificates that are:
# - From Apple OR Google (OR)
# - Using EC keys (AND)
# - Currently valid (AND)
cert-dump -R --org Apple --org Google --key-algo ec --valid /path
```

#### Filtering Examples

**Security Auditing:**
```bash
# Find weak certificates with SHA-1
cert-dump -R --sig-algo sha1 /path

# Find small RSA keys
cert-dump -R --key-algo rsa --key-size 1024 /path

# Find expired certificates
cert-dump -R --expired --dump -o expired_certs /path
```

**Certificate Inventory:**
```bash
# Catalog by vendor
cert-dump -R --org Apple --sqlite apple.db /System/Library/Keychains
cert-dump -R --org DigiCert --sqlite digicert.db /System/Library/Keychains

# Catalog by algorithm
cert-dump -R --key-algo ec --json /path > ec_certs.jsonl
```

**Combined with Other Features:**
```bash
# Extract filtered certificates
cert-dump -R --org Apple --key-algo ec --dump -o apple_ec /path

# Filter and visualize in tree format
cert-dump -R --org "Let's Encrypt" --tree /path

# Filter and export to JSON
cert-dump -R --expired --json /path | jq 'select(.public_key_bits < 2048)'

# Use verbose mode to see filtering statistics
cert-dump -R --org Apple -v /path
# Output: Filtered out 250 certificate(s) that didn't match criteria
```

**Migration Planning:**
```bash
# Find legacy algorithm usage
cert-dump -R --sig-algo md5 /path
cert-dump -R --sig-algo sha1 /path

# Find modern certificates (SHA-256 with strong keys)
cert-dump -R --sig-algo sha256 --key-size 2048 --key-size 4096 /path
```

For complete filtering documentation with all algorithm variants and advanced examples, see [FILTERING.md](FILTERING.md).

### Certificate Tree Visualization

The `--tree` flag displays certificates in a hierarchical tree format, showing parent-child signing relationships. This helps visualize certificate chains and understand trust relationships within PKI hierarchies.

#### Overview

The tree view automatically:
- Links certificates based on issuer/subject Distinguished Names (DNs)
- Identifies root certificates (self-signed)
- Nests child certificates beneath their signing parents
- Shows certificate details inline with proper indentation

#### Basic Usage

```bash
# Display all certificates in tree format
cert-dump --recursive /path/to/certs --tree

# Single file with certificate chain
cert-dump cert-chain.pem --tree

# Analyze system certificate stores
cert-dump -R --tree /System/Library/Keychains/
```

#### Output Format

The tree displays:
- **Certificate number** - Unique index in scan
- **Subject DN** - Identifying information (truncated to 60 chars)
- **Serial number** - Hex-encoded serial
- **Issuer DN** - Who signed this certificate (for non-self-signed)
- **Root marker** - `[ROOT/Self-Signed]` for self-signed certificates

**Example Output:**
```
Certificate Relationship Tree
================================================================================

Certificate #0 CN=Root CA, O=Example Corp, C=US [ROOT/Self-Signed]
   Serial: 0E068A98C23823B2F51C1734E83B156D1F4E9401
   └─ Certificate #2 CN=Intermediate CA, O=Example Corp, C=US
      Serial: 1095E96F97590B45E75F3276DFB31B933D90BAA1
      Issued by: CN=Root CA, O=Example Corp, C=US
      └─ Certificate #1 CN=example.com, O=Example Corp, C=US
         Serial: 0E3D9F6C511979EB0F88418DB048905F5D39B560
         Issued by: CN=Intermediate CA, O=Example Corp, C=US
```

#### Combined with Filtering

Tree view works seamlessly with all filtering options:

```bash
# Show only RSA certificates and their relationships
cert-dump -R --tree --key-algo rsa /path/to/certs

# Visualize only valid certificates from a specific organization
cert-dump -R --tree --valid --org "Let's Encrypt" /path

# Show expired certificate chains
cert-dump -R --tree --expired /path

# Find and visualize specific certificate types
cert-dump -R --tree --key-algo ec --key-size 384 /path
```

#### Use Cases

**Analyzing System Certificate Stores:**
```bash
# macOS system roots
cert-dump -R --tree /System/Library/Keychains/

# Linux system CA bundle
cert-dump --tree /etc/ssl/certs/ca-certificates.crt
```

**Verifying Certificate Chains:**
```bash
# Check if leaf certificate chains to expected root
cert-dump -R --tree ./certificate-bundle/
```

**Auditing PKI Hierarchies:**
```bash
# Find all certificates signed by a specific CA
cert-dump -R --tree --issuer "Intermediate CA" /pki/
```

**Debugging TLS Issues:**
```bash
# Visualize certificate relationships in TLS bundle
cert-dump --tree server-bundle.pem
```

#### Technical Details

**Linking Logic:**
- Certificates are linked when child's Issuer DN matches parent's Subject DN
- Self-signed certificates (Subject DN == Issuer DN) are treated as roots
- Orphan certificates (no parent found) are listed separately

**Performance:**
- O(n) tree construction using hash-based DN lookups
- Efficient even for large certificate stores (thousands of certificates)
- Circular reference protection prevents infinite loops

**Limitations:**
- Links by DN only, not by cryptographic signature verification
- Long DNs truncated to 60 characters for readability
- First match used when multiple certificates share same Subject DN

For complete tree visualization documentation including advanced scenarios and examples, see [TREE.md](TREE.md).

### Performance

`cert-dump` is optimized for speed:

*   Uses `memchr` for fast pattern matching in large binaries
*   Minimal allocations during scanning
*   Efficient DER length parsing without backtracking
*   Parallel multi-threaded architecture for directory scanning
*   Work-stealing queue for load balancing across CPU cores
*   SHA-256 fingerprinting with efficient hash-based deduplication (O(1) duplicate checks)
*   Hard link detection to avoid redundant I/O

**Typical performance:**
*   Single file: Multi-megabyte binaries scanned in milliseconds
*   Directory scanning: Scales linearly with file count and available CPU cores
*   Memory usage: O(unique certificates) — duplicate tracking stores only fingerprints and minimal metadata
*   Default: Uses all available CPU cores; configurable with `--threads`

### Notes

**Single-file mode:**
*   Certificates are reported in file offset order, not in any cryptographic chain order
*   The tool may detect the same certificate multiple times if it appears in both DER and PEM formats at different offsets (this is intentional to support forensic analysis)
*   Original output format is preserved for backward compatibility

**Directory scanning mode:**
*   Triggered automatically when multiple files are specified, `-R` flag is used, or any duplicate-detection flags are active
*   Duplicate detection is based on SHA-256 fingerprints of DER-encoded certificate data
*   Global certificate index is assigned in discovery order (may not be deterministic across runs due to parallel processing)
*   Use `--unique-only` to see only first occurrences, or `--mark-duplicates` to annotate all occurrences
*   Extension filtering is case-insensitive
*   Hidden files are included by default
*   Symbolic links are not followed by default; use `--follow-symlinks` to change this behavior
*   Maximum file size limit (default 512MB) protects against excessive memory usage

**General:**
*   Corrupted or partial certificates may be detected but will fail parsing; use `-v` to see warnings
*   Post-Quantum Cryptography support includes experimental and provisional OIDs that may change as standards finalize
*   Key sizes for PQC algorithms represent security parameter sizes, not classical bit-strength equivalents

### License

MIT License

Copyright (c) 2025 Kenan Sulayman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
