# Certificate Tree Visualization

The `--tree` flag displays certificates in a hierarchical tree format, showing parent-child signing relationships. This helps visualize certificate chains and understand trust relationships.

## Overview

The tree view automatically:
- Links certificates based on issuer/subject Distinguished Names (DNs)
- Identifies root certificates (self-signed)
- Nests child certificates beneath their signing parents
- Shows certificate details inline

## Usage

### Basic Tree View

```bash
# Display all certificates in tree format
cert-dump --recursive /path/to/certs --tree
```

### With Filtering

The tree view works seamlessly with all filtering options:

```bash
# Show only certificates from a specific organization
cert-dump --recursive /path/to/certs --tree --org "DigiCert"

# Show only RSA certificates and their relationships
cert-dump --recursive /path/to/certs --tree --key-algo rsa

# Show only expired certificates in tree format
cert-dump --recursive /path/to/certs --tree --expired
```

### Single File Mode

Works with single files too:

```bash
cert-dump cert-chain.pem --tree
```

## Output Format

The tree displays:
- **Certificate number** - Unique index in scan
- **Subject DN** - Identifying information (truncated to 60 chars)
- **Serial number** - Hex-encoded serial
- **Issuer DN** - Who signed this certificate (for non-self-signed)
- **Root marker** - `[ROOT/Self-Signed]` for self-signed certificates

### Example Output

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

Unlinked Certificates (no parent found in scan)
--------------------------------------------------------------------------------
  Certificate #5 CN=Another Root, O=Different Org, C=FR
```

## Technical Details

### Linking Logic

Certificates are linked when:
1. Child certificate's **Issuer DN** matches parent certificate's **Subject DN**
2. Certificates have different indices (prevents self-references)

### Root Detection

A certificate is considered a root if:
- It's self-signed (Subject DN == Issuer DN), OR
- Its issuer is not found in the scanned certificate set

### Unlinked Certificates

Certificates that don't appear in the main tree (no parent found in the scan) are listed separately at the bottom. These may be:
- Root certificates from other chains
- Certificates whose parent wasn't scanned
- Orphaned intermediate certificates

### Duplicate Handling

When used with `--unique-only`, only unique certificates appear in the tree. Duplicates are excluded before tree construction.

## Use Cases

### 1. Analyzing System Certificate Stores

```bash
# macOS system roots
cert-dump --recursive /System/Library/Keychains/ --tree

# Linux system CA bundle
cert-dump /etc/ssl/certs/ca-certificates.crt --tree
```

### 2. Verifying Certificate Chains

```bash
# Check if leaf certificate chains to expected root
cert-dump --recursive ./chain/ --tree
```

### 3. Auditing PKI Hierarchies

```bash
# Find all certificates signed by a specific CA
cert-dump --recursive /pki/ --tree --issuer "Intermediate CA"
```

### 4. Debugging TLS Issues

```bash
# Visualize certificate relationships in TLS bundle
cert-dump server-bundle.pem --tree
```

### 5. Compliance Audits

```bash
# Show only RSA 2048+ certificates in tree format
cert-dump --recursive /company/pki/ --tree --key-algo rsa --key-size 2048
```

## Combining with Other Output Options

### Extract and Visualize

```bash
# Extract certificates and show their relationships
cert-dump --recursive /path/ --tree --dump
```

### Filter and Visualize

```bash
# Show only valid certificates in tree format
cert-dump --recursive /certs/ --tree --valid
```

### Cannot Combine With

The `--tree` flag is mutually exclusive with:
- `--json` (JSON output)
- Standard tabular output

If both are specified, tree output takes precedence.

## Performance

Tree building is efficient:
- **O(n)** certificate parsing
- **O(n)** DN mapping
- **O(n)** tree construction
- **O(n)** rendering

Large certificate stores (thousands of certificates) render quickly.

## Limitations

1. **No signature verification**: The tree links certificates by DN only, not by cryptographic signature verification
2. **Truncation**: Long DNs are truncated to 60 characters for readability
3. **Same DN handling**: If multiple certificates share the same Subject DN, the first match is used as parent
4. **Display only**: Tree view is for visualization; use `--dump` to extract certificates

## Tips

- Use `--verbose` for additional scanning context (doesn't affect tree output)
- Combine with `--mark-duplicates` to see which unique certificates have duplicates
- Filter before tree generation to focus on specific certificate types
- Use `--unique-only` to exclude duplicate certificates from the tree

## See Also

- [README.md](README.md) - Main documentation
- [FILTERING.md](FILTERING.md) - Certificate filtering options
- [JSON_SQLITE.md](JSON_SQLITE.md) - JSON and SQLite output formats
