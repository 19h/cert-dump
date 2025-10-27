# JSON and SQLite Output Features

## Overview

The `cert-dump` tool now supports multiple output formats for certificate scanning results, enabling integration with automated workflows, data analysis pipelines, and database-driven applications.

## JSON Output

### Format

Newline-delimited JSON (JSONL/NDJSON) format where each line is a complete JSON object representing one certificate.

### Fields

```json
{
  "global_index": 0,
  "path": "./test.pem",
  "offset": 0,
  "size": 610,
  "sha256": "0381c8036660395523d844a9529d99e3f730751383cd5c8bbd37bbc5b94b6d9e",
  "source": "PEM",
  "is_duplicate": false,
  "duplicate_of": null,
  "subject": "CN=Example",
  "issuer": "CN=Example CA",
  "serial": "A1C70A055953974E",
  "not_before": "2024-01-01T00:00:00+00:00",
  "not_after": "2025-01-01T00:00:00+00:00",
  "public_key_algorithm": "RSA",
  "public_key_bits": 2048,
  "signature_algorithm": "sha256WithRSAEncryption"
}
```

### Duplicate Information

When a certificate is a duplicate, the `duplicate_of` field contains:

```json
{
  "duplicate_of": {
    "sha256": "0381c8036660395523d844a9529d99e3f730751383cd5c8bbd37bbc5b94b6d9e",
    "global_index": 0,
    "path": "./first-occurrence.pem",
    "offset": 0,
    "size": 610,
    "occurrences": 3
  }
}
```

### Usage Examples

**Basic JSON output:**
```bash
cert-dump -R --json /path/to/directory > results.jsonl
```

**JSON with unique certificates only:**
```bash
cert-dump -R --json --unique-only /directory > unique.jsonl
```

**JSON with duplicate annotations:**
```bash
cert-dump -R --json --mark-duplicates /directory > all-with-dupes.jsonl
```

**Processing with jq:**
```bash
# Extract all SHA-256 fingerprints
cert-dump -R --json /dir | jq -r '.sha256'

# Find certificates expiring soon
cert-dump -R --json /dir | jq 'select(.not_after < "2025-01-01")'

# Count duplicates
cert-dump -R --json /dir | jq 'select(.is_duplicate) | .sha256' | sort | uniq -c

# Find all RSA certificates
cert-dump -R --json /dir | jq 'select(.public_key_algorithm == "RSA")'

# Extract unique subjects
cert-dump -R --json /dir | jq -r '.subject' | sort -u
```

## SQLite Output

### Database Schema

The SQLite database contains two main tables:

**`certificate` table** (unique certificates):
```sql
CREATE TABLE certificate (
    sha256 TEXT PRIMARY KEY,
    subject TEXT,
    issuer TEXT,
    serial TEXT,
    not_before TEXT,
    not_after TEXT,
    public_key_algorithm TEXT,
    public_key_bits INTEGER,
    signature_algorithm TEXT,
    first_seen_path TEXT NOT NULL,
    first_seen_offset INTEGER NOT NULL,
    first_seen_size INTEGER NOT NULL,
    first_seen_global_index INTEGER NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1
);
```

**`occurrence` table** (all occurrences):
```sql
CREATE TABLE occurrence (
    sha256 TEXT NOT NULL,
    path TEXT NOT NULL,
    offset INTEGER NOT NULL,
    size INTEGER NOT NULL,
    global_index INTEGER NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (sha256, path, offset),
    FOREIGN KEY (sha256) REFERENCES certificate(sha256) ON DELETE CASCADE
);
```

### Indexes

The following indexes are automatically created for query performance:
- `idx_occurrence_sha256` on `occurrence(sha256)`
- `idx_occurrence_path` on `occurrence(path)`
- `idx_certificate_subject` on `certificate(subject)`
- `idx_certificate_issuer` on `certificate(issuer)`

### Usage Examples

**Basic SQLite export:**
```bash
cert-dump -R --sqlite certs.db /path/to/directory
```

**Query unique certificates:**
```bash
sqlite3 certs.db "SELECT sha256, subject, occurrence_count FROM certificate;"
```

**Find all occurrences of a specific certificate:**
```bash
sqlite3 certs.db "
  SELECT path, offset, size
  FROM occurrence
  WHERE sha256='0381c8036660395523d844a9529d99e3f730751383cd5c8bbd37bbc5b94b6d9e'
  ORDER BY path;
"
```

**Find duplicate certificates (count > 1):**
```bash
sqlite3 certs.db "
  SELECT sha256, subject, occurrence_count
  FROM certificate
  WHERE occurrence_count > 1
  ORDER BY occurrence_count DESC;
"
```

**Find certificates in a specific directory:**
```bash
sqlite3 certs.db "
  SELECT DISTINCT c.subject, c.sha256, c.occurrence_count
  FROM certificate c
  JOIN occurrence o ON c.sha256 = o.sha256
  WHERE o.path LIKE '/specific/directory/%';
"
```

**Find certificates by issuer:**
```bash
sqlite3 certs.db "
  SELECT sha256, subject, issuer, occurrence_count
  FROM certificate
  WHERE issuer LIKE '%Let''s Encrypt%';
"
```

**Export to CSV:**
```bash
sqlite3 -header -csv certs.db "SELECT * FROM certificate;" > certificates.csv
```

**Generate statistics:**
```bash
sqlite3 certs.db "
  SELECT
    COUNT(*) as unique_certificates,
    SUM(occurrence_count) as total_occurrences,
    AVG(occurrence_count) as avg_occurrences,
    MAX(occurrence_count) as max_occurrences
  FROM certificate;
"
```

**Find RSA certificates:**
```bash
sqlite3 certs.db "
  SELECT sha256, subject, public_key_bits
  FROM certificate
  WHERE public_key_algorithm = 'RSA'
  ORDER BY public_key_bits;
"
```

**Find expiring certificates:**
```bash
sqlite3 certs.db "
  SELECT sha256, subject, not_after
  FROM certificate
  WHERE not_after < datetime('now', '+30 days')
  ORDER BY not_after;
"
```

## Combined Output

You can use both JSON and SQLite output simultaneously:

```bash
cert-dump -R --json --sqlite certs.db /directory > results.jsonl
```

This allows you to:
- Stream JSON results to stdout for real-time processing
- Store complete data in SQLite for later analysis
- Combine with other tools in a pipeline

## Integration Examples

### Python Integration

**Read JSON output:**
```python
import json

with open('results.jsonl') as f:
    for line in f:
        cert = json.loads(line)
        if cert['is_duplicate']:
            print(f"Duplicate: {cert['sha256']} in {cert['path']}")
```

**Query SQLite:**
```python
import sqlite3

conn = sqlite3.connect('certs.db')
cursor = conn.cursor()

# Find all RSA certificates
cursor.execute("""
    SELECT sha256, subject, public_key_bits
    FROM certificate
    WHERE public_key_algorithm = 'RSA'
""")

for row in cursor.fetchall():
    print(f"{row[1]}: {row[2]} bits")
```

### Bash Pipeline

```bash
# Find and analyze duplicates
cert-dump -R --json /path | \
  jq -r 'select(.is_duplicate) | [.sha256, .path] | @csv' | \
  sort | \
  uniq -c | \
  sort -rn
```

### Data Analysis

```bash
# Generate summary report
cert-dump -R --sqlite analysis.db /path

sqlite3 analysis.db << 'EOF'
.mode column
.headers on

SELECT
  public_key_algorithm as Algorithm,
  COUNT(*) as Count,
  ROUND(AVG(public_key_bits), 0) as AvgBits,
  MIN(public_key_bits) as MinBits,
  MAX(public_key_bits) as MaxBits
FROM certificate
WHERE public_key_bits IS NOT NULL
GROUP BY public_key_algorithm
ORDER BY Count DESC;
EOF
```

## Performance Considerations

### JSON
- Streaming output (O(1) memory)
- Ideal for piping to other tools
- Fast parsing with `jq`, Python's `json` module, etc.

### SQLite
- Batch writes with transactions (high performance)
- Indexes for fast queries
- WAL mode for concurrent reads
- Database size: ~1-2KB per unique certificate + ~100 bytes per occurrence

### Recommendations
- Use `--unique-only` to reduce output size when duplicates aren't needed
- For very large scans (100k+ files), consider piping JSON directly instead of collecting in memory
- SQLite handles millions of certificates efficiently
- Use `--json` for streaming, `--sqlite` for analysis

## Notes

- JSON fields are omitted if null/empty (e.g., `subject` is omitted if parsing failed)
- SQLite database uses UTF-8 encoding
- Timestamps in JSON are RFC3339 format
- Timestamps in SQLite are ISO8601 strings compatible with SQLite's datetime functions
- SHA-256 fingerprints are lowercase hex strings (64 characters)
- The `global_index` is assigned in discovery order (may not be deterministic across runs due to parallelism)

## Error Handling

- Parse failures: Certificate is included with null/omitted metadata fields
- SQLite write errors: Reported to stderr, scanning continues
- JSON serialization errors: Reported to stderr, scanning continues
- Both outputs respect `--verbose` for detailed diagnostics

## See Also

- [README.md](README.md) - Main documentation
- [FILTERING.md](FILTERING.md) - Certificate filtering options
- [TREE.md](TREE.md) - Displaying Certificate Relationship Tree
