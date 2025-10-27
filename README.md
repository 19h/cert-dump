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

`cert-dump` is a command-line utility for scanning binary files to find embedded X.509 certificates. It supports both DER (Distinguished Encoding Rules) and PEM (Privacy-Enhanced Mail) formats, providing detailed certificate information and optional extraction capabilities.

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

### Features

*   **Fast Binary Scanning:** Uses optimized pattern matching (`memchr`) to efficiently scan large binaries for both DER and PEM certificate formats.
*   **Dual Format Support:** Detects certificates in both DER (raw binary ASN.1) and PEM (Base64-encoded) formats.
*   **Detailed Certificate Metadata:** Displays comprehensive information including:
    *   Subject and Issuer Distinguished Names (DN)
    *   Serial number
    *   Validity period (Not Before/Not After dates)
    *   Public key algorithm and size (RSA, EC, Ed25519, Ed448)
    *   Signature algorithm
    *   File offset and size
*   **Flexible Extraction:** Extract certificates in DER format, PEM format, or both (default).
*   **Diskutil-Style Output:** Clean, colored terminal output with proper alignment and visual hierarchy.
*   **Verbose Mode:** Additional details including DER lengths, PEM block offsets, and parse diagnostics.

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

**Signature Algorithms Recognized:**
*   RSA with MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
*   ECDSA with SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
*   EdDSA (Ed25519, Ed448)
*   SM2 with SM3

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
*   Parallel-friendly architecture (single-threaded for now)

Typical performance: Scans multi-megabyte binaries in milliseconds on modern hardware.

### Notes

*   Certificates are reported in file offset order, not in any cryptographic chain order
*   The tool may detect the same certificate multiple times if it appears in both DER and PEM formats at different offsets (this is intentional to support forensic analysis)
*   Corrupted or partial certificates may be detected but will fail parsing; use `-v` to see warnings

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
