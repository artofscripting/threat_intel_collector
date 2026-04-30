# Threat Intel Collector

Dockerized network listener that captures visible traffic, extracts IOC-style fields, and writes events into PostgreSQL.

Current behavior:
- PostgreSQL is the only output sink (CSV output is disabled).
- Traffic with local/private addresses is excluded from inserts.
- A startup PostgreSQL self-test is logged immediately.

## Complete Install And Run (GitHub -> .env -> Build -> Compose Start)

1. Clone the repository.

```bash
git clone https://github.com/artofscripting/threat_intel_collector.git
cd threat_intel_collector
```

2. Create your environment file from the template.

```bash
cp .env.example .env
```

3. Edit `.env` and set your values.

```bash
nano .env
```

Minimum required field:

```dotenv
HONEY_POSTGRES_PASSWORD=your_real_password_here
```

Recommended fields to set:

```dotenv
SOURCE_NAME=honeypot-1
INTERFACE=auto
BPF_FILTER=
ENABLE_RDNS=false
ENABLE_RDAP=true
PAYLOAD_MAX_BYTES=1024
FLUSH_INTERVAL=1
POSTGRES_HOST=switchyard.proxy.rlwy.net
POSTGRES_PORT=13718
POSTGRES_DB=railway
POSTGRES_USER=postgres
POSTGRES_TABLE=threat_intel_events
```

4. Build the Docker image.

```bash
docker build -t threat-intel-listener .
```

5. Start with Docker Compose.

```bash
docker compose up -d --build
```

6. Verify startup and PostgreSQL connectivity.

```bash
docker logs threat-intel-listener
```

You should see lines similar to:
- `[*] PostgreSQL self-test OK: ...`
- `[*] PostgreSQL enabled, writing to table ...`

7. Check service status.

```bash
docker compose ps
```

## Pull Updates From GitHub

From inside the repo directory:

```bash
git pull origin main
docker compose up -d --build
```

## Stop / Restart

Stop:

```bash
docker compose down
```

Restart with rebuild:

```bash
docker compose up -d --build
```

## Ubuntu One-Step Installer

For interactive setup on Ubuntu (installs Docker/Compose if needed, prompts for values including source name, writes `.env`, and starts service):

```bash
chmod +x ./install_ubuntu.sh
./install_ubuntu.sh
```

## Empty PostgreSQL Table

PowerShell helper:

```powershell
pwsh ./empty_table.ps1
```

Dry run:

```powershell
pwsh ./empty_table.ps1 -DryRun
```

## Configuration Reference

The compose file reads `.env` via `env_file` and maps these runtime variables:
- `SOURCE_NAME`
- `INTERFACE`
- `BPF_FILTER`
- `ENABLE_RDNS`
- `ENABLE_RDAP`
- `PAYLOAD_MAX_BYTES`
- `FLUSH_INTERVAL`
- `POSTGRES_HOST`
- `POSTGRES_PORT`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `HONEY_POSTGRES_PASSWORD`
- `POSTGRES_TABLE`

## Notes

- Host networking with raw packet capture works best on Linux hosts.
- Container runs with `privileged`, `NET_ADMIN`, and `NET_RAW` to enable sniffing.
- "All protocols" means all IP traffic visible on the selected interface; deep app-layer parsing is intentionally lightweight.

