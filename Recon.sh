
#!/usr/bin/env bash

# Recon - Automated Subdomain Reconnaissance
# Intended for authorized security testing.

set -Eeuo pipefail

# --------------------------------------------------
# Configuration
# --------------------------------------------------

DOMAIN="${1:-}"

TARGETS_DIR="${TARGETS_DIR:-/targets}"
WORDLIST="${WORDLIST:-/tools/words/subdomainmix.txt}"
MASSDNS_BIN="${MASSDNS_BIN:-/tools/massdns/bin/massdns}"
RESOLVERS="${RESOLVERS:-/tools/resolver.txt}"
SUBLIST3R_SCRIPT="${SUBLIST3R_SCRIPT:-/tools/Sublist3r/sublist3r.py}"
PYTHON_BIN="${PYTHON_BIN:-/tools/pyenv/bin/python}"
HTTPX_BIN="${HTTPX_BIN:-/root/go/bin/httpx}"
NUCLEI_TEMPLATE="${NUCLEI_TEMPLATE:-$HOME/nuclei-templates/ssl/ssl-dns-names.yaml}"

WEBHOOK_URL="${RECON_WEBHOOK_URL:-}"

REQUEST_TIMEOUT=30

# --------------------------------------------------
# Utility functions
# --------------------------------------------------

log() {
    printf '[*] %s\n' "$1"
}

error() {
    printf '[!] %s\n' "$1" >&2
}

die() {
    error "$1"
    exit 1
}

check_command() {
    command -v "$1" >/dev/null 2>&1 ||
        die "Required command not found: $1"
}

check_file() {
    [[ -f "$1" && -r "$1" ]] ||
        die "Required file is missing or unreadable: $1"
}

# --------------------------------------------------
# Input validation
# --------------------------------------------------

if [[ -z "$DOMAIN" || $# -ne 1 ]]; then
    echo "Usage: $0 <domain.com>"
    exit 1
fi

DOMAIN="${DOMAIN,,}"

if [[ ${#DOMAIN} -gt 253 ]] ||
   [[ ! "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]; then
    die "Invalid domain format."
fi

# --------------------------------------------------
# Dependency verification
# --------------------------------------------------

for cmd in curl jq sort gau subfinder nuclei dnsgen shuffledns; do
    check_command "$cmd"
done

check_file "$WORDLIST"
check_file "$RESOLVERS"
check_file "$MASSDNS_BIN"
check_file "$SUBLIST3R_SCRIPT"
check_file "$PYTHON_BIN"
check_file "$HTTPX_BIN"
check_file "$NUCLEI_TEMPLATE"

# --------------------------------------------------
# Output directory
# --------------------------------------------------

mkdir -p "$TARGETS_DIR"

TARGETS_DIR="$(cd "$TARGETS_DIR" && pwd -P)"
RESULTS_DIR="$TARGETS_DIR/$DOMAIN"

if [[ -L "$RESULTS_DIR" ]]; then
    die "Target directory cannot be a symbolic link."
fi

mkdir -p "$RESULTS_DIR"

if [[ "$(realpath "$RESULTS_DIR")" != "$RESULTS_DIR" ]]; then
    die "Unexpected target directory resolution."
fi

# Prevent simultaneous runs against the same target.
if ! mkdir "$RESULTS_DIR/.recon.lock" 2>/dev/null; then
    die "Another reconnaissance process may already be running."
fi

WORK_DIR="$(mktemp -d "$RESULTS_DIR/.recon.XXXXXX")"

cleanup() {
    rm -rf -- "$WORK_DIR"
    rmdir "$RESULTS_DIR/.recon.lock" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

START_TIME=$(date +%s)

# --------------------------------------------------
# Certificate Transparency
# --------------------------------------------------

crtsh() {
    curl -fsS --max-time "$REQUEST_TIMEOUT" \
        --get \
        --data-urlencode "q=%.$DOMAIN" \
        --data-urlencode "output=json" \
        "https://crt.sh/" |
        jq -r '.[].common_name // empty' |
        tr '[:upper:]' '[:lower:]' |
        sort -u
}

# --------------------------------------------------
# Nuclei certificate extraction
# --------------------------------------------------

get_certificate_nuclei() {
    printf '%s\n' "$DOMAIN" |
        nuclei \
            -t "$NUCLEI_TEMPLATE" \
            -silent \
            -j |
        jq -r '.["extracted-results"][]? // empty' |
        sort -u
}

# --------------------------------------------------
# Passive discovery
# --------------------------------------------------

log "Starting reconnaissance for $DOMAIN"

log "Running Subfinder..."

subfinder -d "$DOMAIN" -silent \
    -o "$WORK_DIR/subfinder.txt"

log "Running GAU..."

gau --subs --threads 30 "$DOMAIN" |
    unfurl domains |
    sort -u > "$WORK_DIR/gau.txt"

log "Running Sublist3r..."

"$PYTHON_BIN" "$SUBLIST3R_SCRIPT" \
    -d "$DOMAIN" \
    -o "$WORK_DIR/sublist3r.txt"

log "Retrieving certificate transparency records..."

crtsh > "$WORK_DIR/crtsh.txt"

# --------------------------------------------------
# Aggregate passive results
# --------------------------------------------------

log "Aggregating passive discovery results..."

sort -u \
    "$WORK_DIR/subfinder.txt" \
    "$WORK_DIR/gau.txt" \
    "$WORK_DIR/sublist3r.txt" \
    "$WORK_DIR/crtsh.txt" |
    tr '[:upper:]' '[:lower:]' |
    sort -u > "$WORK_DIR/subdomains.txt"

cp "$WORK_DIR/subdomains.txt" "$RESULTS_DIR/subdomains.txt"

log "Passive discovery completed."

# --------------------------------------------------
# First-level DNS brute-forcing
# --------------------------------------------------

log "Running first-level ShuffleDNS brute-force..."

shuffledns \
    -w "$WORDLIST" \
    -d "$DOMAIN" \
    -m "$MASSDNS_BIN" \
    -r "$RESOLVERS" \
    -l "$RESULTS_DIR/subdomains.txt" \
    -mode bruteforce \
    -o "$WORK_DIR/sub1stlev.txt"

# --------------------------------------------------
# DNS permutation generation
# --------------------------------------------------

log "Generating DNS permutations..."

dnsgen "$WORK_DIR/sub1stlev.txt" \
    > "$WORK_DIR/permutations.txt"

# --------------------------------------------------
# Second-level DNS brute-forcing
# --------------------------------------------------

log "Running second-level ShuffleDNS brute-force..."

shuffledns \
    -w "$WORDLIST" \
    -d "$DOMAIN" \
    -m "$MASSDNS_BIN" \
    -r "$RESOLVERS" \
    -l "$WORK_DIR/permutations.txt" \
    -mode bruteforce \
    -o "$WORK_DIR/sub2ndlev.txt"

# --------------------------------------------------
# Aggregate brute-force results
# --------------------------------------------------

log "Combining brute-force results..."

sort -u \
    "$WORK_DIR/sub1stlev.txt" \
    "$WORK_DIR/sub2ndlev.txt" \
    > "$RESULTS_DIR/bruteforce_result.txt"

sort -u \
    "$RESULTS_DIR/subdomains.txt" \
    "$RESULTS_DIR/bruteforce_result.txt" \
    > "$WORK_DIR/final_subdomains.txt"

cp "$WORK_DIR/final_subdomains.txt" \
    "$RESULTS_DIR/subdomains.txt"

log "Subdomain discovery completed."

# --------------------------------------------------
# HTTP probing
# --------------------------------------------------

log "Probing discovered subdomains using httpx..."

"$HTTPX_BIN" \
    -l "$RESULTS_DIR/subdomains.txt" \
    -silent \
    -o "$WORK_DIR/httpx_raw.txt"

# Keep only URLs belonging to the requested domain.
awk -v d="$DOMAIN" '
{
    host = tolower($0)
    sub(/^[a-z]+:\/\//, "", host)
    sub(/[\/?#].*/, "", host)
    sub(/:[0-9]+$/, "", host)

    if (
        host == d ||
        (
            length(host) > length(d) &&
            substr(host, length(host)-length(d), 1) == "." &&
            substr(host, length(host)-length(d)+1) == d
        )
    ) {
        print
    }
}
' "$WORK_DIR/httpx_raw.txt" |
    sort -u > "$RESULTS_DIR/live_subdomains.txt"

# --------------------------------------------------
# Certificate-based extraction
# --------------------------------------------------

log "Extracting certificate DNS names using Nuclei..."

get_certificate_nuclei \
    > "$RESULTS_DIR/domains.txt"

# --------------------------------------------------
# Optional webhook notification
# --------------------------------------------------

if [[ -n "$WEBHOOK_URL" ]]; then
    log "Sending completion notification..."

    curl -fsS \
        --max-time "$REQUEST_TIMEOUT" \
        -X POST \
        --data-urlencode "recon on $DOMAIN was successful" \
        "$WEBHOOK_URL" >/dev/null ||
        error "Webhook notification failed."
fi

# --------------------------------------------------
# Execution statistics
# --------------------------------------------------

END_TIME=$(date +%s)
ELAPSED_TIME=$((END_TIME - START_TIME))

printf '%s seconds\n' "$ELAPSED_TIME" |
    tee "$RESULTS_DIR/elapsed_time"

log "Reconnaissance completed successfully."
log "Target: $DOMAIN"
log "Results: $RESULTS_DIR"
log "Discovered subdomains: $(wc -l < "$RESULTS_DIR/subdomains.txt")"
log "Live HTTP services: $(wc -l < "$RESULTS_DIR/live_subdomains.txt")"
log "Execution time: $ELAPSED_TIME seconds"
