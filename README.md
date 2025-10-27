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
    *   Extension-based file filtering (e.g., `--ext exe,dll,jar,apk`)
    *   Maximum file size limits to skip oversized files
    *   Hard link detection to avoid scanning the same content twice
    *   Symlink traversal control
*   **Multiple Output Formats:**
    *   **Text:** Human-readable colored terminal output with proper formatting
    *   **JSON:** Newline-delimited JSON with full certificate metadata and duplicate tracking
    *   **SQLite:** Relational database with `certificate` and `occurrence` tables for complex queries
    *   Can combine formats (e.g., `--json --sqlite` for both outputs simultaneously)
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
