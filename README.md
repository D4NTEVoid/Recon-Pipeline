# Recon Pipeline

An automated subdomain reconnaissance pipeline designed for bug bounty hunters and penetration testers.

Recon Pipeline combines multiple passive discovery sources, DNS brute-forcing techniques, DNS permutation generation, and HTTP probing into a single automated workflow.

## Features

- **Passive Subdomain Discovery:** Collects subdomains using Subfinder, GAU, Sublist3r, and crt.sh.
- **Certificate Transparency:** Retrieves domain information from public certificate records.
- **DNS Brute-Forcing:** Discovers additional subdomains using ShuffleDNS and MassDNS.
- **DNS Permutation Generation:** Generates potential subdomain variations using DNSGen.
- **Multi-Level Discovery:** Performs two rounds of DNS brute-forcing.
- **HTTP Probing:** Identifies responding web services using httpx.
- **Certificate Analysis:** Extracts additional DNS names using Nuclei templates.
- **Result Aggregation:** Combines and deduplicates discovered domains.
- **Execution Statistics:** Records execution time and discovery statistics.
- **Webhook Notifications:** Supports optional completion notifications through a configurable webhook.

## Tools & Dependencies

This project integrates the following tools:

| Tool | Purpose |
|---|---|
| Subfinder | Passive subdomain discovery |
| GAU | URL collection from public sources |
| Unfurl | Domain extraction from URLs |
| Sublist3r | Subdomain enumeration |
| crt.sh | Certificate Transparency lookup |
| ShuffleDNS | DNS resolution and brute-forcing |
| MassDNS | High-performance DNS resolution |
| DNSGen | Subdomain permutation generation |
| httpx | HTTP service discovery |
| Nuclei | Certificate-related DNS name extraction |
| jq | JSON processing |
| curl | HTTP requests |

See [docs/dependencies.md](docs/dependencies.md) for installation and configuration details.

## Requirements

- Linux environment
- Bash
- Python 3
- Go-based reconnaissance utilities
- Configured DNS resolvers
- Subdomain wordlist
- Nuclei templates

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/recon-pipeline.git
cd recon-pipeline
```

Make the script executable:

```bash
chmod +x Recon.sh
```

Install and configure the required dependencies according to the documentation.

## Configuration

The script supports environment variables for customizing its paths:

| Variable | Default |
|---|---|
| `TARGETS_DIR` | `/targets` |
| `WORDLIST` | `/tools/words/subdomainmix.txt` |
| `MASSDNS_BIN` | `/tools/massdns/bin/massdns` |
| `RESOLVERS` | `/tools/resolver.txt` |
| `SUBLIST3R_SCRIPT` | `/tools/Sublist3r/sublist3r.py` |
| `PYTHON_BIN` | `/tools/pyenv/bin/python` |
| `HTTPX_BIN` | `/root/go/bin/httpx` |
| `NUCLEI_TEMPLATE` | `$HOME/nuclei-templates/ssl/ssl-dns-names.yaml` |

Example:

```bash
export TARGETS_DIR="$HOME/recon/targets"
export WORDLIST="$HOME/wordlists/subdomains.txt"
```

### Optional Webhook Notifications

Notifications are disabled by default.

To enable them:

```bash
export RECON_WEBHOOK_URL="https://your-server.example/webhook"
```

The script sends a completion notification containing the target domain.

## Usage

```bash
./Recon.sh example.com
```

Replace `example.com` with the authorized target domain.

## Workflow

1. Passive subdomain enumeration.
2. Certificate Transparency collection.
3. Result aggregation and deduplication.
4. First-level DNS brute-forcing.
5. DNS permutation generation.
6. Second-level DNS brute-forcing.
7. Final subdomain aggregation.
8. HTTP probing and live service identification.
9. Certificate-based DNS name extraction.
10. Optional webhook notification and execution statistics.

## Output Structure

Results are stored in a separate directory for each target.

```text
targets/
└── example.com/
    ├── subdomains.txt
    ├── bruteforce_result.txt
    ├── live_subdomains.txt
    ├── domains.txt
    └── elapsed_time
```

| File | Description |
|---|---|
| `subdomains.txt` | Aggregated discovered subdomains |
| `bruteforce_result.txt` | Results from DNS brute-forcing |
| `live_subdomains.txt` | HTTP-responsive endpoints |
| `domains.txt` | Certificate-derived DNS names |
| `elapsed_time` | Total execution time in seconds |

## Responsible Use

This tool is intended for authorized security research, penetration testing, and bug bounty reconnaissance.

- Only perform reconnaissance against domains you are authorized to assess.
- Respect bug bounty program scope and testing policies.
- Be aware that DNS brute-forcing and HTTP probing generate traffic to external infrastructure.
- Use appropriate concurrency and rate limits.
- Do not interpret discovered subdomains as automatically in-scope assets.

## Disclaimer

This project is provided for educational and authorized security testing purposes. The author is not responsible for misuse, unauthorized testing, or damage resulting from the use of this software.

## License

MIT License (subject to confirmation of licensing rights and applicable third-party tool licenses).
