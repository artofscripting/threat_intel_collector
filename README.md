# Threat Intel Listener (Docker)

This container captures inbound and outbound packets, writes threat-intel-style telemetry to CSV, and can mirror each event into PostgreSQL.

## What it collects

- Source/destination IP and ports
- Transport and IP protocol numbers (TCP/UDP/other)
- Packet size, TTL/HopLimit, TCP flags
- Payload hash (`sha256`) and Base64 payload (truncated by `PAYLOAD_MAX_BYTES`)
- Simple IOC extraction from payload:
  - URLs
  - IPs
  - Domains
  - CVE IDs
  - Hash-like strings (MD5/SHA1/SHA256)
- Reverse DNS (optional)
- RDAP/ASN enrichment for public source IPs (optional)
- Basic scan-likeness flag (for SYN-only/empty probes)
- Optional PostgreSQL insert for each captured event

## Files

- `collector.py`: packet capture + enrichment + CSV writer
- `docker-compose.yml`: easiest run option
- `Dockerfile`: image build
- Output CSV: `./data/threat_intel.csv`

## Run

```bash
docker compose up --build -d
```

## Ubuntu install script

Use the interactive installer to install Docker/Compose (if needed), prompt for config (including source name), write `.env`, and start the service:

```bash
chmod +x ./install_ubuntu.sh
./install_ubuntu.sh
```

The compose file reads [.env](.env) for database secrets.

Tail logs:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

## Empty the PostgreSQL table

Run this from the project folder:

```powershell
pwsh ./empty_table.ps1
```

Optional dry run:

```powershell
pwsh ./empty_table.ps1 -DryRun
```

## CSV output fields

- `timestamp_utc`
- `src_ip`, `dst_ip`
- `src_port`, `dst_port`
- `transport`, `ip_proto`
- `packet_len`, `ttl_hoplimit`, `tcp_flags`
- `service_guess`, `is_scan_like`
- `ioc_ips`, `ioc_domains`, `ioc_urls`, `ioc_hashes`, `ioc_cves`
- `payload_sha256`, `payload_b64`
- `rdns`
- `is_private`, `is_reserved`, `is_multicast`
- `country`, `asn`, `asn_description`, `whois_network`

## Environment variables

- `CSV_FILE` (default `/data/threat_intel.csv`)
- `INTERFACE` (default `auto`; prefers `any` if available, else first non-loopback)
- `BPF_FILTER` (default empty; example: `tcp or udp`)
- `ENABLE_RDNS` (`false` by default)
- `ENABLE_RDAP` (`true` by default)
- `PAYLOAD_MAX_BYTES` (`1024` by default)
- `FLUSH_INTERVAL` (`1` by default)
- `POSTGRES_DSN` (optional explicit DSN; if unset, app builds DSN from vars below)
- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD` (from [.env](.env))
- `POSTGRES_TABLE` (`threat_intel_events` by default)

## PostgreSQL configuration

Set password in [.env](.env):

```env
HONEY_POSTGRES_PASSWORD=postgress
```

By default, compose passes host/port/db/user and the app builds:

```text
postgresql://postgres:${POSTGRES_PASSWORD}@switchyard.proxy.rlwy.net:13718/railway
```

## Notes and limitations

- Capturing "all protocols" in practice means all IP traffic visible on the selected interface. The script records protocol numbers even when not TCP/UDP.
- Deep application decoding (full HTTP parser, DNS parser, TLS fingerprinting, etc.) is intentionally not included to keep this lightweight.
- `network_mode: host` is best on Linux hosts. On Docker Desktop for Windows/macOS, host networking and packet visibility can be limited.
- Running with `privileged`/`NET_RAW`/`NET_ADMIN` is required for packet sniffing in most environments.

## Optional filter examples

Set in `docker-compose.yml` environment:

- Capture only inbound internet scans to common ports:
  - `BPF_FILTER: "tcp[tcpflags] & tcp-syn != 0 and (dst port 22 or dst port 23 or dst port 3389 or dst port 445)"`
- Capture DNS + HTTP/S:
  - `BPF_FILTER: "port 53 or port 80 or port 443"`

