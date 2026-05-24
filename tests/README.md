# KOTA tests

**Automated** checks (no cluster) run via **CMake / `ctest`**. **Manual** scripts need root, Kubernetes, and often Cilium-style networking or a GPU. Design: [`docs/flow.md`](../docs/flow.md).

`kotad` now supports OpenTelemetry metrics SDK linkage via `opentelemetry-cpp` (pinned to `v1.17.0` in CMake). Metrics build is enabled by default and can be disabled for constrained/offline builds with `-DKOTA_OTEL=OFF`.

### OTLP metrics export (collector path)

Metrics use a **PeriodicExportingMetricReader** plus an **OTLP/HTTP metric exporter**.

- **`OTEL_EXPORTER_OTLP_ENDPOINT`** and **`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`** (standard OpenTelemetry C++ conventions) configure the OTLP base URL when set; the SDK builds the HTTP metrics path (typically `…/v1/metrics`). If neither is set, the SDK default applies (see `opentelemetry-cpp` `GetOtlpDefaultHttpMetricsEndpoint()` — commonly `http://localhost:4318/v1/metrics`).
- **`KOTA_OTEL_EXPORT_INTERVAL_MS`** — export cadence for the periodic reader (default `3000`).
- **`KOTA_OTEL_DEBUG=1`** — extra OTLel bridge logging.
- Fail-soft: OTLP unreachable does not stop `kotad`; on Linux a **one-line** stderr notice may appear once if the OTLP TCP port rejects connections shortly after startup.
- Collector YAML: [`../kota/deploy/otelcol-demo.yaml`](../kota/deploy/otelcol-demo.yaml) (OTLP `:4318`, Prometheus exporter `0.0.0.0:9091`).

### Prometheus scrape surface (V3.7 — OTel-only path **A**)

Grafana Prometheus datasource points at **`http://127.0.0.1:9091`** (collector `prometheus` exporter). **`kotad` does not expose `:9091` itself**: it emits **OTLP/HTTP metrics only**. There is **no second** Prometheus registry in-process (no `prometheus-cpp`), matching the sprint DO NOT.

**End-to-end data path (collector architecture):**

1. `kotad` creates instruments on the OTel **`Meter`** and exports via **`PeriodicExportingMetricReader`**.
2. The OTel OTLP **HTTP** exporter sends resource + metric points to **`OTEL_EXPORTER_OTLP_ENDPOINT`** (default semantics in `otel_exporter.cpp`; usually `localhost:4318` → OTLP path `/v1/metrics`).
3. **OpenTelemetry Collector** receives OTLP on **`:4318`** (`receivers.otlp.protocols.http`).
4. The collector **`prometheus` exporter** binds **`0.0.0.0:9091`** (see YAML) and serves Prometheus exposition text (**`/metrics`**). With Docker **`--publish 9091:9091`**, the host uses **`http://127.0.0.1:9091/metrics`**.
5. **Grafana** scrapes that URL; instrument names from **OTel → OTLP → collector** typically appear with **`kota_`** / **`kotad_`** prefixes (Prometheus label names may be normalized).

**Smoke check:**

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
# Collector (example Docker) — mount YAML as a file path (not a directory):
# docker run --rm -it -p 4318:4318 -p 9091:9091 \
#   -v "$PWD/kota/deploy/otelcol-demo.yaml:/etc/otelcol/config.yaml:ro" \
#   otel/opentelemetry-collector:latest --config /etc/otelcol/config.yaml
curl -sSf 127.0.0.1:9091/metrics | grep -E 'kota_|kotad_'
```

### Grafana dashboard (V3.8)

**Dashboard JSON** (four rows, aligned with [`../docs/tasks/demo.md`](../docs/tasks/demo.md)):

- [`../docs/grafana/kota-demo.json`](../docs/grafana/kota-demo.json)

**Import — Grafana 10+:** **Dashboards → New → Import** → upload **`kota-demo.json`**. Pick your **Prometheus** datasource when the **`ds_prometheus`** variable prompts (metrics must come from the collector scrape on **`:9091`**, same as §Prometheus scrape surface above).

**Lab checklist — V2.1 fault:** With [`manual/e2e_network_gpu.sh`](manual/e2e_network_gpu.sh) driving NVML violate/recover, **ROW 2** should visibly correlate **GPU temperature** (spike/rise) with **verdict state** (ACTIVE↔VIOLATION). No secrets are stored in the JSON.

**Note:** If you previously created **`deploy/otelcol-demo.yaml` as a directory** by incorrect Docker bind-mount, remove it manually (`sudo rm -rf`), then recreate a **file** or symlink — see authoritative config under **`kota/deploy/`**.

### Protobuf/gRPC C++ codegen for `kotad` (V4.4 input)

Generate C++ protobuf and gRPC service stubs from `api/kota_control_plane.proto`:

```bash
cd /path/to/KOTA
mkdir -p api/gen/cpp
protoc -I api \
  --cpp_out=api/gen/cpp \
  --grpc_out=api/gen/cpp \
  --plugin=protoc-gen-grpc="$(command -v grpc_cpp_plugin)" \
  api/kota_control_plane.proto
```

Expected outputs:

- `api/gen/cpp/kota_control_plane.pb.h`
- `api/gen/cpp/kota_control_plane.pb.cc`
- `api/gen/cpp/kota_control_plane.grpc.pb.h`
- `api/gen/cpp/kota_control_plane.grpc.pb.cc`

## `scripts/check_kota_env.sh`

Quick **machine check** before you spend time on BPF or `kotad`. It does not start KOTA.

- Makes sure the **BPF mount** exists at `/sys/fs/bpf` and tells you if it is not writable when that would block pinning maps.
- Makes sure **`bpftool`** is on your `PATH`.
- If the kernel **config file** is readable, checks that **BPF** and **BTF** support look enabled for this project, and **warns** if BPF LSM is off (some enforcement paths will not work on that kernel).
- **Warns** if **`nvidia-smi`** is missing so you know GPU-related checks may not apply.

**Exit 0** = required checks passed (warnings are still OK). **Non-zero** = fix the errors it prints. Optional: `--json` for a one-line summary object.

## Automated tests (`ctest`)

From your build directory (after `cmake` + `cmake --build`):

| `ctest -R …` | What it checks |
|--------------|----------------|
| `pod_resolver_parse` | Cgroup-style paths → container ID and pod UID parsing. |
| `pod_resolver_oci_profile_golden` | Minimal OCI JSON ([`fixtures/oci/kota_profile_label_golden.json`](fixtures/oci/kota_profile_label_golden.json)) → `kota.ai/profile` string. |
| `policy_profile_decision` | Profile YAML + decision logic using [`fixtures/profiles/`](fixtures/profiles/). |

Example:

```bash
ctest --test-dir build -R 'pod_resolver_parse|pod_resolver_oci_profile_golden|policy_profile_decision'
```

## Manual

- [`manual/e2e_network_gpu.sh`](manual/e2e_network_gpu.sh) — full lifecycle smoke (see script comments; logs often under `tests/results/`).

### `e2e_network_gpu.sh` (default path)

- Default behavior is NVML-driven verdict transitions (no direct verdict map poke).
- Script requires a lab-safe GPU stress command through:
  - `KOTA_E2E_GPU_STRESS_CMD='<your stress command>'`
- Debug fallback map poke is still available (temporary) via:
  - `KOTA_E2E_DEBUG_POKE=1`

Example (default NVML path):

```bash
cd /path/to/KOTA
export KOTA_E2E_GPU_STRESS_CMD='cd /path/to/gpu-burn && ./gpu_burn 120'
sudo -E bash tests/manual/e2e_network_gpu.sh
```

Useful env knobs:

- `KOTA_E2E_TELEMETRY_PROFILE` (default: `tests/fixtures/profiles/nvml_fault_injection_lab.yaml`)
- `KOTA_E2E_VIOLATION_TIMEOUT_S` (default: `120`)
- `KOTA_E2E_RECOVERY_TIMEOUT_S` (default: `120`)
- `KOTA_NVML_POLL_MS` (default in script: `1000`)
- `KOTA_E2E_PREFLIGHT_API_CHECK` (default: `1`)
- `KOTA_E2E_REQUIRE_CILIUM` (default: `1`; set `0` only for non-golden-path debugging)

### Cilium / `lxc*` golden path checklist

The script now enforces golden-path preflight and returns **exit 77** (skip) when
the required Cilium tier is missing.

Checklist (manual visibility):

```bash
kubectl -n kube-system get ds cilium
ls /sys/fs/bpf/tc/globals/cilium_ipcache
ip -o link show | awk -F': ' '{print $2}' | grep '^lxc'
```

Skip behavior:

- If Cilium daemonset is not ready: script exits `77`.
- If `cilium_ipcache` map is missing: script exits `77`.
- If no host `lxc*` interface exists: script exits `77`.

Runtime note:

- Resolver/attach log lines are printed as informational evidence only.
- Script pass/fail does **not** depend on exact log string matching.

### Copy/paste runbook (prevention)

Preflight + build + run:

```bash
cd /path/to/KOTA

kubectl get nodes -o custom-columns='NAME:.metadata.name,ALLOCATABLE_GPU:.status.allocatable.nvidia\.com/gpu,CAPACITY_GPU:.status.capacity.nvidia\.com/gpu'
kubectl get pods -A -o wide | rg -i 'cilium|nvidia|device-plugin|gpu-operator' || true

# Script preflight uses an in-cluster curl probe and expects a real HTTP code from
# https://10.43.0.1/version (401 is fine; 000 is treated as unreachable).

cmake -S . -B build
cmake --build build -j

export KOTA_E2E_GPU_STRESS_CMD='cd /path/to/gpu-burn && ./gpu_burn 120'
export KOTA_E2E_VIOLATION_TIMEOUT_S=180
export KOTA_E2E_RECOVERY_TIMEOUT_S=180
sudo -E bash tests/manual/e2e_network_gpu.sh
```

Live logs (separate terminal):

```bash
cd /path/to/KOTA
sudo tail -f tests/results/kotad_e2e.log
```

Post-run cleanup:

```bash
cd /path/to/KOTA
kubectl delete pod kota-test-workload --force --grace-period=0 2>/dev/null || true
kubectl delete pod kota-e2e-api-check --force --grace-period=0 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/kota
```

Fast debug fallback (temporary):

```bash
cd /path/to/KOTA
export KOTA_E2E_DEBUG_POKE=1
sudo -E bash tests/manual/e2e_network_gpu.sh
```

## NVML fault injection contract (lab)

Goal: drive `StatusMap` verdict transitions from NVML telemetry only (no manual
`bpftool map update`) and verify both latch and hysteresis-clear behavior.

1. Use the dedicated lab profile:
   - `tests/fixtures/profiles/nvml_fault_injection_lab.yaml`
2. Start a stress workload to breach the temperature threshold in the profile.
3. Verify logs show debounced violation:
   - `[KOTA] NVML violation pending: ... reason=...`
   - `[KOTA] NVML violation latched: ... reason=...`
   - `[KOTA] NVML debounced transition -> VIOLATION`
4. Stop stress and let the GPU cool below threshold.
5. Verify hysteresis recovery:
   - `[KOTA] NVML recovery pending: healthy_streak=X/Y`
   - `[KOTA] NVML recovery completed: clear hysteresis satisfied (...)`
   - `[KOTA] NVML debounced transition -> ACTIVE`

Example dry-run invocation (non-enforcing):

```bash
KOTA_NVML_POLL_MS=1000 \
KOTA_NVML_DEBOUNCE_VIOLATION=3 \
KOTA_NVML_DEBOUNCE_CLEAR=3 \
KOTA_NVML_DRY_RUN_ITERS=30 \
./build/kota/kotad --dry-run-telemetry \
  --telemetry-profile tests/fixtures/profiles/nvml_fault_injection_lab.yaml
```

Non-GPU hosts:

- `kotad --dry-run-telemetry` exits `0` when NVML is unavailable and prints:
  `[KOTA] telemetry dry-run: NVML unavailable: ... (exits 0)`
- Treat this as an expected skip path for acceptance on machines without
  NVIDIA hardware or drivers.

**Tuning:** environment variables and flags for `kotad` are described in `kotad --help` and in [`docs/`](../docs/).
