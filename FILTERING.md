# Certificate Filtering

## Overview

The `cert-dump` tool supports comprehensive filtering of certificates based on various fields. All filters use **fuzzy matching** (case-insensitive, substring search) and can be specified multiple times for OR logic.

## Filter Options

### Distinguished Name (DN) Fields

Filter by components of the certificate's Subject or Issuer DN:

| Flag | Description | Example |
|------|-------------|---------|
| `--org <ORG>` | Organization (O) | `--org Apple --org Microsoft` |
| `--ou <OU>` | Organizational Unit (OU) | `--ou "Engineering"` |
| `--common <COMMON>` | Common Name (CN) | `--common "*.apple.com"` |
| `--country <COUNTRY>` | Country (C) | `--country US --country GB` |
| `--locality <LOCALITY>` | Locality (L) | `--locality "San Francisco"` |
| `--state <STATE>` | State/Province (ST) | `--state California` |

**Matching:** Searches in both Subject and Issuer fields. Case-insensitive substring match.

### Full DN Filters

| Flag | Description | Example |
|------|-------------|---------|
| `--subject <TEXT>` | Full Subject DN | `--subject "Apple Inc"` |
| `--issuer <TEXT>` | Full Issuer DN | `--issuer "DigiCert"` |

**Matching:** Case-insensitive substring search across the entire DN string.

### Certificate Identifiers

| Flag | Description | Example |
|------|-------------|---------|
| `--serial <SERIAL>` | Serial number | `--serial 1A2B3C` |
| `--sha256 <HASH>` | SHA-256 fingerprint | `--sha256 da98f640` |

**Matching:** Case-insensitive substring match (hex values).

### Cryptographic Algorithms

#### Public Key Algorithm (`--key-algo`)

Supports smart variant matching:

| Filter Value | Matches |
|--------------|---------|
| `rsa` | Any RSA algorithm |
| `rsa-pss`, `pss` | RSA-PSS specifically |
| `ec`, `ecc` | Any elliptic curve algorithm |
| `ecdsa` | ECDSA specifically |
| `ed25519` | Ed25519 |
| `ed448` | Ed448 |
| `eddsa` | Ed25519 or Ed448 |
| `dsa` | DSA |
| `dilithium`, `ml-dsa` | Post-quantum Dilithium/ML-DSA |
| `kyber`, `ml-kem` | Post-quantum Kyber/ML-KEM |
| `sm2` | Chinese SM2 |
| `gost` | Russian GOST |

**Example:**
```bash
# Find all EC certificates
cert-dump -R --key-algo ec /path

# Find RSA-PSS certificates
cert-dump -R --key-algo pss /path
```

#### Signature Algorithm (`--sig-algo`)

Supports smart variant matching:

| Filter Value | Matches |
|--------------|---------|
| `sha` | Any SHA-based signature |
| `sha1`, `sha-1` | SHA-1 specifically |
| `sha2` | SHA-256, SHA-384, or SHA-512 |
| `sha256`, `sha-256` | SHA-256 specifically |
| `sha384`, `sha-384` | SHA-384 specifically |
| `sha512`, `sha-512` | SHA-512 specifically |
| `rsa` | Any RSA signature |
| `ecdsa` | ECDSA signatures |
| `eddsa` | EdDSA signatures |
| `md5` | MD5 signatures |

**Example:**
```bash
# Find certificates with SHA-256 signatures
cert-dump -R --sig-algo sha256 /path

# Find any SHA-2 family signature
cert-dump -R --sig-algo sha2 /path
```

### Key Size

| Flag | Description | Example |
|------|-------------|---------|
| `--key-size <BITS>` | Public key size in bits | `--key-size 2048 --key-size 4096` |

**Note:** Only matches certificates where the key size can be determined. Multiple values create an OR filter.

**Example:**
```bash
# Find 2048-bit or 4096-bit RSA keys
cert-dump -R --key-algo rsa --key-size 2048 --key-size 4096 /path
```

### Validity Period

| Flag | Description |
|------|-------------|
| `--expired` | Show only expired certificates (not_after < now) |
| `--valid` | Show only currently valid certificates |

**Note:** `--expired` and `--valid` are mutually exclusive.

**Example:**
```bash
# Find expired Apple certificates
cert-dump -R --expired --org Apple /System/Library/Keychains

# Find currently valid RSA certificates
cert-dump -R --valid --key-algo rsa /path
```

## Filter Logic

### Multiple Values (OR Logic)

When you specify the same flag multiple times, certificates matching **any** of the values are included (OR logic):

```bash
# Find certificates from Apple OR Microsoft
cert-dump -R --org Apple --org Microsoft /path
```

### Multiple Flags (AND Logic)

When you specify different flags, certificates must match **all** filters (AND logic):

```bash
# Find Apple certificates that use EC keys
cert-dump -R --org Apple --key-algo ec /path
```

### Complex Example

```bash
# Find certificates that are:
# - From Apple OR Google
# - Using EC keys
# - With 384-bit keys
# - Currently valid
cert-dump -R --org Apple --org Google --key-algo ec --key-size 384 --valid /path
```

## Usage Examples

### Basic Filtering

```bash
# Find all Entrust certificates
cert-dump -R --org Entrust /System/Library/Keychains

# Find all EC certificates
cert-dump -R --key-algo ec /System/Library/Keychains

# Find 4096-bit RSA certificates
cert-dump -R --key-algo rsa --key-size 4096 /path
```

### Advanced Filtering

```bash
# Find expired RSA certificates from any CA
cert-dump -R --expired --key-algo rsa /path

# Find Apple's elliptic curve certificates
cert-dump -R --org "Apple" --key-algo ec --dump -o apple_ec /System/Library/Keychains

# Find certificates expiring soon (already expired + issued before 2025)
cert-dump -R --expired /path

# Find modern certificates (SHA-256 with strong keys)
cert-dump -R --sig-algo sha256 --key-size 2048 --key-size 4096 /path
```

### Combining with Other Features

#### With Unique Mode
```bash
# Find unique expired certificates
cert-dump -R --unique-only --expired /path
```

#### With Extraction
```bash
# Extract all Apple EC certificates
cert-dump -R --org Apple --key-algo ec --dump -o apple_ec_certs /path
```

#### With JSON Output
```bash
# Export filtered results as JSON
cert-dump -R --org "Let's Encrypt" --json /path > letsencrypt.jsonl

# Process with jq
cert-dump -R --expired --json /path | jq 'select(.public_key_bits < 2048)'
```

#### With SQLite
```bash
# Store filtered certificates in database
cert-dump -R --org Apple --key-algo ec --sqlite apple_ec.db /path

# Query later
sqlite3 apple_ec.db "SELECT subject, not_after FROM certificate ORDER BY not_after"
```

### Verbose Mode

Use `-v` to see filtering statistics:

```bash
cert-dump -R --org Apple -v /System/Library/Keychains
# Output includes:
# Filtered out 250 certificate(s) that didn't match criteria
```

## Real-World Scenarios

### Security Auditing

**Find weak certificates:**
```bash
# Find certificates with SHA-1 signatures (deprecated)
cert-dump -R --sig-algo sha1 /path

# Find certificates with keys smaller than 2048 bits
cert-dump -R --key-algo rsa --key-size 1024 /path
```

**Find expired certificates:**
```bash
cert-dump -R --expired --dump -o expired_certs /path
```

### Certificate Inventory

**Catalog by vendor:**
```bash
# Apple certificates
cert-dump -R --org Apple --sqlite apple.db /System/Library/Keychains

# DigiCert certificates
cert-dump -R --org DigiCert --sqlite digicert.db /System/Library/Keychains
```

**Catalog by algorithm:**
```bash
# All EC certificates
cert-dump -R --key-algo ec --json /path > ec_certs.jsonl

# All RSA-PSS certificates
cert-dump -R --key-algo pss --json /path > pss_certs.jsonl
```

### Certificate Renewal Planning

**Find certificates expiring soon:**
```bash
# Get all expired certificates (already past renewal)
cert-dump -R --expired --json /path > expired.jsonl

# Find short-lived certificates (already expired)
cert-dump -R --expired --org "Let's Encrypt" /path
```

### Migration Planning

**Find legacy algorithm usage:**
```bash
# Find MD5 certificates
cert-dump -R --sig-algo md5 /path

# Find SHA-1 certificates
cert-dump -R --sig-algo sha1 /path

# Find old RSA keys that need upgrading
cert-dump -R --key-algo rsa --key-size 1024 --key-size 512 /path
```

## Performance

- **Filtering is performed during scanning**, so it's very efficient
- **No post-processing overhead** - filtered certificates are never loaded into memory
- **Verbose mode** shows how many certificates were filtered out
- **Combine with `--unique-only`** to further reduce results

## Tips

1. **Start broad, then narrow:** Begin with one filter and add more to refine results
   ```bash
   cert-dump -R --org Apple /path        # See all Apple certs
   cert-dump -R --org Apple --key-algo ec /path  # Narrow to EC only
   ```

2. **Use verbose mode** to understand filtering impact:
   ```bash
   cert-dump -R --org Apple -v /path
   ```

3. **Test filters with JSON** for easy inspection:
   ```bash
   cert-dump -R --org Apple --json /path | head -5
   ```

4. **Combine with extraction** to save filtered certificates:
   ```bash
   cert-dump -R --expired --dump -o expired /path
   ```

5. **Use substring matching** to your advantage:
   ```bash
   --org "Let"  # Matches "Let's Encrypt", "Lettuce Inc", etc.
   --serial "1A"  # Matches any serial containing "1A"
   ```

## Notes

- All text matching is **case-insensitive**
- All text matching uses **substring search** (fuzzy)
- Algorithm matching has **smart variant support** (e.g., "sha" matches "sha256WithRSAEncryption")
- Filters apply to **both subject and issuer** for DN fields
- Parse failures are excluded when filters are active (unless no filters are set)
- Filtering works in both **single-file** and **directory** modes
- Filtering works with **all output formats** (text, JSON, SQLite)

## See Also

- [README.md](README.md) - Main documentation
- [JSON_SQLITE.md](JSON_SQLITE.md) - JSON and SQLite output formats
- [TREE.md](TREE.md) - Displaying Certificate Relationship Tree
