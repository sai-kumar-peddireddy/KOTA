#!/usr/bin/env bash
# One-shot start/stop for OTEL collector + Prometheus + Grafana (docs/tasks/setup.md § metrics).
# Does not start kotad (that stays manual / systemd with OTEL_EXPORTER_OTLP_ENDPOINT).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly NETWORK="kota-metrics"
readonly OTEL_CONFIG="${ROOT}/kota/deploy/otelcol-demo.yaml"
readonly PROM_CONFIG="${ROOT}/kota/deploy/prometheus-scrape-otel.yaml"

die() { echo "error: $*" >&2; exit 1; }

need_file() { [[ -f "$1" ]] || die "missing file: $1"; }

wait_http_ok() {
  local url=$1
  local label=$2
  local max=${3:-45}
  local i=0
  while (( i < max )); do
    if curl -sfS --max-time 3 "$url" >/dev/null 2>&1; then
      echo "ok: $label ($url)"
      return 0
    fi
    (( ++i ))
    sleep 1
  done
  die "timeout waiting for $label ($url)"
}

wait_json_success() {
  local url=$1
  local label=$2
  local max=${3:-45}
  local i=0
  while (( i < max )); do
    if out=$(curl -sfS --max-time 5 "$url" 2>/dev/null) && echo "$out" | grep -q '"status":"success"'; then
      echo "ok: $label"
      return 0
    fi
    (( ++i ))
    sleep 1
  done
  die "timeout waiting for $label ($url)"
}

cmd_start() {
  need_file "$OTEL_CONFIG"
  need_file "$PROM_CONFIG"

  command -v docker >/dev/null || die "docker not found"
  docker info >/dev/null 2>&1 || die "docker not usable (permission/daemon?)"

  echo "[*] Creating Docker network ${NETWORK} (if needed)"
  docker network create "$NETWORK" 2>/dev/null || true

  echo "[*] Starting kota-otelcol (4318 OTLP, 9091 metrics exposition)"
  docker rm -f kota-otelcol 2>/dev/null || true
  docker run --rm -d --name kota-otelcol --network "$NETWORK" \
    -p 4318:4318 -p 9091:9091 \
    -v "${OTEL_CONFIG}:/etc/otelcol/config.yaml:ro" \
    otel/opentelemetry-collector:latest --config /etc/otelcol/config.yaml

  echo "[*] Starting kota-prometheus (9090 PromQL API; scrapes kota-otelcol:9091)"
  docker rm -f kota-prometheus 2>/dev/null || true
  docker run --rm -d --name kota-prometheus --network "$NETWORK" \
    -p 9090:9090 \
    -v "${PROM_CONFIG}:/etc/prometheus/prometheus.yml:ro" \
    prom/prometheus:latest \
    --config.file=/etc/prometheus/prometheus.yml

  echo "[*] Starting kota-grafana (3000)"
  docker rm -f kota-grafana 2>/dev/null || true
  docker run --rm -d --name kota-grafana --network "$NETWORK" \
    -p 3000:3000 \
    grafana/grafana:latest

  sleep 2
  echo "[*] Waiting for endpoints on localhost..."
  wait_http_ok "http://127.0.0.1:9091/metrics" "OTel /metrics" 60
  wait_http_ok "http://127.0.0.1:9090/-/healthy" "Prometheus /-/healthy" 60
  wait_http_ok "http://127.0.0.1:3000/api/health" "Grafana /api/health" 90

  echo "[*] Prometheus query API smoke (works before kotad runs; result may be empty)"
  wait_json_success "http://127.0.0.1:9090/api/v1/query?query=kota_otel_startup_total" "Prometheus /api/v1/query" 30

  echo "[*] Scrape target health (from kota-metrics network)"
  if docker run --rm --network "$NETWORK" curlimages/curl:8.5.0 -sfS --max-time 10 \
    "http://kota-prometheus:9090/api/v1/targets" | grep -q '"health":"up"'; then
    echo "ok: at least one Prometheus target reports health=up"
  else
    echo "warn: could not confirm scrape target UP yet (wait a few seconds and re-run: $0 status)"
  fi

  echo
  echo "[*] Stack is up."
  echo "    OTLP for kotad:  http://127.0.0.1:4318"
  echo "    Grafana UI:      http://127.0.0.1:3000  (datasource URL inside Grafana: http://kota-prometheus:9090)"
  echo "    Prometheus UI:   http://127.0.0.1:9090"
  echo "    Raw OTel text:   http://127.0.0.1:9091/metrics"
  echo
  echo "Next: run kotad with OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 (see docs/tasks/setup.md)."
}

cmd_stop() {
  command -v docker >/dev/null || die "docker not found"
  echo "[*] Stopping metrics stack containers"
  for c in kota-grafana kota-prometheus kota-otelcol; do
    docker rm -f "$c" 2>/dev/null || true
  done
  if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "[*] Removing Docker network ${NETWORK}"
    docker network rm "$NETWORK" 2>/dev/null || {
      echo "warn: network ${NETWORK} still in use; disconnect remaining containers or: docker network inspect ${NETWORK}"
    }
  fi
  echo "[*] Done. (kotad/systemd and k8s workloads are unchanged.)"
}

cmd_status() {
  command -v docker >/dev/null || die "docker not found"
  echo "[*] Containers"
  docker ps -a --filter "name=kota-" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
  echo
  echo "[*] Quick probes (localhost)"
  curl -sfS --max-time 3 "http://127.0.0.1:9091/metrics" >/dev/null && echo "  9091/metrics: ok" || echo "  9091/metrics: down"
  curl -sfS --max-time 3 "http://127.0.0.1:9090/-/healthy" >/dev/null && echo "  Prometheus: ok" || echo "  Prometheus: down"
  curl -sfS --max-time 3 "http://127.0.0.1:3000/api/health" >/dev/null && echo "  Grafana: ok" || echo "  Grafana: down"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") {start|stop|status}

  start   Create ${NETWORK}, run OTEL collector + Prometheus + Grafana, verify HTTP health.
  stop    Remove kota-grafana, kota-prometheus, kota-otelcol and ${NETWORK}.
  status  Show containers and probe localhost ports.

Repo layout expected from: ${ROOT}
EOF
}

main() {
  case "${1:-}" in
    start)  cmd_start ;;
    stop)   cmd_stop ;;
    status) cmd_status ;;
    *)      usage; exit 1 ;;
  esac
}

main "$@"
