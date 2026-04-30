#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

echo "=== Threat Intel Listener Ubuntu Installer ==="

echo "This script will:"
echo "1) Install Docker + Compose plugin (if missing)"
echo "2) Prompt for runtime settings"
echo "3) Write .env"
echo "4) Build and start the container"

default_if_empty() {
  local value="$1"
  local fallback="$2"
  if [[ -z "$value" ]]; then
    echo "$fallback"
  else
    echo "$value"
  fi
}

prompt_value() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="$3"
  local input
  read -r -p "$prompt_text [$default_value]: " input
  printf -v "$var_name" "%s" "$(default_if_empty "$input" "$default_value")"
}

prompt_secret() {
  local var_name="$1"
  local prompt_text="$2"
  local input
  read -r -s -p "$prompt_text: " input
  echo
  if [[ -z "$input" ]]; then
    echo "Password cannot be empty." >&2
    exit 1
  fi
  printf -v "$var_name" "%s" "$input"
}

ensure_sudo() {
  if [[ "$EUID" -eq 0 ]]; then
    return
  fi

  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required for package installation." >&2
    exit 1
  fi

  sudo -v
}

install_docker_if_needed() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "Docker and Compose plugin already installed."
    return
  fi

  echo "Installing Docker and Compose plugin..."
  ensure_sudo
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  sudo install -m 0755 -d /etc/apt/keyrings

  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  local arch codename
  arch="$(dpkg --print-architecture)"
  codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
  echo "deb [arch=$arch signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $codename stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  if ! groups "$USER" | grep -q '\bdocker\b'; then
    sudo usermod -aG docker "$USER"
    echo "Added $USER to docker group. You may need to log out/in for non-sudo docker commands."
  fi
}

if [[ ! -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
  echo "docker-compose.yml not found in $SCRIPT_DIR" >&2
  exit 1
fi

install_docker_if_needed

echo
echo "Enter runtime settings (press Enter to accept defaults)."

prompt_value SOURCE_NAME "Source name label" "honeypot-1"
prompt_value INTERFACE "Capture interface" "auto"
prompt_value BPF_FILTER "BPF filter" ""
prompt_value ENABLE_RDNS "Enable reverse DNS (true/false)" "false"
prompt_value ENABLE_RDAP "Enable RDAP enrichment (true/false)" "true"
prompt_value PAYLOAD_MAX_BYTES "Payload max bytes" "1024"
prompt_value FLUSH_INTERVAL "Flush interval packets" "1"

prompt_value POSTGRES_HOST "PostgreSQL host" "switchyard.proxy.rlwy.net"
prompt_value POSTGRES_PORT "PostgreSQL port" "13718"
prompt_value POSTGRES_DB "PostgreSQL database" "railway"
prompt_value POSTGRES_USER "PostgreSQL user" "postgres"
prompt_secret HONEY_POSTGRES_PASSWORD "PostgreSQL password"
prompt_value POSTGRES_TABLE "PostgreSQL table" "threat_intel_events"

if [[ -f "$ENV_FILE" ]]; then
  cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%Y%m%d%H%M%S)"
fi

cat > "$ENV_FILE" <<EOF
SOURCE_NAME=$SOURCE_NAME
INTERFACE=$INTERFACE
BPF_FILTER=$BPF_FILTER
ENABLE_RDNS=$ENABLE_RDNS
ENABLE_RDAP=$ENABLE_RDAP
PAYLOAD_MAX_BYTES=$PAYLOAD_MAX_BYTES
FLUSH_INTERVAL=$FLUSH_INTERVAL
POSTGRES_HOST=$POSTGRES_HOST
POSTGRES_PORT=$POSTGRES_PORT
POSTGRES_DB=$POSTGRES_DB
POSTGRES_USER=$POSTGRES_USER
HONEY_POSTGRES_PASSWORD=$HONEY_POSTGRES_PASSWORD
POSTGRES_TABLE=$POSTGRES_TABLE
EOF

echo
echo "Wrote $ENV_FILE"

echo "Starting service..."
if docker compose version >/dev/null 2>&1; then
  docker compose up --build -d
else
  sudo docker compose up --build -d
fi

echo
echo "Install complete."
echo "View logs: docker logs -f threat-intel-listener"
