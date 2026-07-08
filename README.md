# Advanced DNS Lookup Tool

Multithreaded DNS enumeration tool supporting A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, NAPTR, and PTR records, with JSON/CSV export.

## Features

- Concurrent lookups across multiple domains (ThreadPoolExecutor)
- Configurable record types, custom nameserver, timeout, and thread count
- Reverse (PTR) lookup on resolved A records
- Colored terminal output
- Export to JSON or CSV
- Batch mode via input file

## Requirements

- Python 3.7+
- `dnspython`

```bash
pip install dnspython
```

## Usage

```bash
python dns_lookup.py <domain> [options]
```

### Examples

```bash
# Basic lookup (default record types)
python dns_lookup.py example.com

# Specific record types
python dns_lookup.py example.com -t A MX NS TXT

# Custom nameserver + reverse lookup
python dns_lookup.py example.com -n 8.8.8.8 -r

# Batch lookup from file, export to JSON
python dns_lookup.py -f domains.txt -o results.json

# Export as CSV
python dns_lookup.py example.com -o results.csv
```

## Options

| Flag | Description |
|---|---|
| `domain` | Domain to look up (positional) |
| `-f, --file` | File of domains, one per line |
| `-t, --types` | Record types to query (default: A AAAA MX NS TXT CNAME SOA) |
| `-n, --nameserver` | Custom DNS server IP |
| `--timeout` | Query timeout in seconds (default: 5.0) |
| `--threads` | Thread pool size (default: 20) |
| `-r, --reverse` | PTR lookup on A record results |
| `--no-color` | Disable colored output |
| `-o, --output` | Export file path (`.json` or `.csv`) |
| `--csv` | Force CSV export format |

## Supported Record Types

`A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `SRV`, `CAA`, `NAPTR`, `PTR`

## Output

**Terminal:** grouped, color-coded results per domain.

**JSON:**
```json
[
  {
    "domain": "example.com",
    "records": { "A": ["93.184.216.34"], "MX": ["..."] },
    "error": null
  }
]
```

**CSV:** `domain, record_type, value` rows.

## Disclaimer

For authorized security assessments and educational use only. Only query domains you own or have explicit permission to test.
