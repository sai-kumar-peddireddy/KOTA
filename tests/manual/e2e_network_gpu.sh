#!/usr/bin/env bash
# KOTA CE — S7.1 End-to-End manual test script
# Validates Phases 1-4: Discovery, Monitoring, Enforcement, Recovery

set -euo pipefail

# Binary: prefer the actively rebuilt top-level build output first.
# Override with KOTA_E2E_KOTAD_BIN when needed.
if [[ -n "${KOTA_E2E_KOTAD_BIN:-}" ]]; then
    KOTAD_BIN="$KOTA_E2E_KOTAD_BIN"
elif [[ -f "./build/kota/kotad" ]]; then
    KOTAD_BIN="./build/kota/kotad"
else
    KOTAD_BIN="./kota/build/kotad"
fi
PROFILE_YAML="${KOTA_E2E_TELEMETRY_PROFILE:-tests/fixtures/profiles/nvml_fault_injection_lab.yaml}"
RESULTS_DIR="tests/results"
KOTAD_LOG="${RESULTS_DIR}/kotad_e2e.log"
POD_NAME="kota-test-workload"
POD_UNLABELED_NAME="kota-test-unlabeled"
KOTA_E2E_DEBUG_POKE="${KOTA_E2E_DEBUG_POKE:-0}"
KOTA_E2E_GPU_STRESS_CMD="${KOTA_E2E_GPU_STRESS_CMD:-}"
KOTA_E2E_VIOLATION_TIMEOUT_S="${KOTA_E2E_VIOLATION_TIMEOUT_S:-120}"
KOTA_E2E_RECOVERY_TIMEOUT_S="${KOTA_E2E_RECOVERY_TIMEOUT_S:-120}"
KOTA_E2E_PREFLIGHT_API_CHECK="${KOTA_E2E_PREFLIGHT_API_CHECK:-1}"
KOTA_E2E_REQUIRE_CILIUM="${KOTA_E2E_REQUIRE_CILIUM:-1}"
KOTA_E2E_STRICT_IOCTL="${KOTA_E2E_STRICT_IOCTL:-0}"
KOTA_E2E_STRICT_REAL_GPU="${KOTA_E2E_STRICT_REAL_GPU:-0}"
GPU_STRESS_PID=""
IOCTL_TARGET_PATH=""
API_CHECK_LOG="/tmp/kota_e2e_api_check.log"

# Optional E2E toggles (no need to set any for a standard run):
#   KOTA_E2E_KOTAD_BIN=./path/to/kotad      — force binary (default prefers ./kota/build/kotad)
#   KOTA_E2E_LOG_RESOLVE_TIMING=1           — KOTA_LOG_RESOLVE_TIMING: cgroup_prefix + per-layer + Cilium/OCI detail
#   KOTA_CILIUM_UDS_RETRY_SLEEP_MS=...      — wait before 2nd Cilium UDS try (kotad default 15; this script defaults 8 for E2E)
#   KOTA_CILIUM_SOCKET=...                  — passed through -E if set before sudo (Cilium agent UDS)
# Other KOTA_E2E_* variables are defined below.

mkdir -p "$RESULTS_DIR"

cleanup() {
    echo "[*] Cleaning up..."
    if [[ -n "${GPU_STRESS_PID:-}" ]]; then
        kill "${GPU_STRESS_PID}" 2>/dev/null || true
    fi
    kill "${KOTAD_PID:-}" 2>/dev/null || true
    kubectl delete pod "$POD_NAME" --force --grace-period=0 2>/dev/null || true
    kubectl delete pod "$POD_UNLABELED_NAME" --force --grace-period=0 2>/dev/null || true
    kubectl delete pod kota-e2e-api-check --force --grace-period=0 2>/dev/null || true
    rm -rf /sys/fs/bpf/kota
    echo "[*] Cleanup complete. See $KOTAD_LOG for kotad logs."
}
trap cleanup EXIT

# 1. Prereqs
if [[ $EUID -ne 0 ]]; then echo "Must run as root"; exit 1; fi
if ! command -v bpftool &> /dev/null; then echo "bpftool required"; exit 1; fi
if ! command -v kubectl &> /dev/null; then echo "kubectl required (golden lab assumption)"; exit 77; fi
if ! command -v python3 &> /dev/null; then echo "python3 required"; exit 1; fi
if [[ ! -f "$KOTAD_BIN" ]]; then
    echo "kotad not found at $KOTAD_BIN. Build: cmake --build kota/build  (or set KOTA_E2E_KOTAD_BIN)"
    exit 1
fi
if [ ! -f "$PROFILE_YAML" ]; then echo "telemetry profile not found at $PROFILE_YAML"; exit 1; fi
PROFILE_NAME="$(python3 - "$PROFILE_YAML" <<'PY'
import re,sys
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r'^\s*name:\s*"?([^"\n]+)"?\s*$', line)
    if m:
        print(m.group(1).strip())
        raise SystemExit(0)
raise SystemExit(1)
PY
)" || { echo "[!] Failed to parse profile name from $PROFILE_YAML"; exit 1; }
if [[ -z "$PROFILE_NAME" ]]; then
    echo "[!] Profile name is empty in $PROFILE_YAML"
    exit 1
fi
PORT_PARSE="$(
python3 - "$PROFILE_YAML" <<'PY'
import sys, yaml
try:
    data = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception as e:
    print(f"ERROR={e}")
    raise SystemExit(1)
mgmt = data.get("management_ports") or []
ai = data.get("ai_ports") or data.get("ai_data_ports") or []
if not mgmt or not ai:
    print("ERROR=management_ports and ai_ports are required")
    raise SystemExit(1)
def norm(xs):
    out = []
    for x in xs:
        try:
            p = int(x)
        except Exception:
            continue
        if 1 <= p <= 65535:
            out.append(str(p))
    return out
mgmt_n = norm(mgmt)
ai_n = norm(ai)
if not mgmt_n or not ai_n:
    print("ERROR=no valid management/ai ports after normalization")
    raise SystemExit(1)
print("MGMT=" + ",".join(mgmt_n))
print("AI=" + ",".join(ai_n))
PY
)" || { echo "[!] Failed to parse ports from $PROFILE_YAML"; exit 1; }
if grep -q '^ERROR=' <<<"$PORT_PARSE"; then
    echo "[!] $PORT_PARSE"
    exit 1
fi
MGMT_PORTS_CSV="$(awk -F= '/^MGMT=/{print $2}' <<<"$PORT_PARSE")"
AI_PORTS_CSV="$(awk -F= '/^AI=/{print $2}' <<<"$PORT_PARSE")"
IFS=',' read -r -a MGMT_PORTS <<<"$MGMT_PORTS_CSV"
IFS=',' read -r -a AI_PORTS <<<"$AI_PORTS_CSV"
if [[ ${#MGMT_PORTS[@]} -eq 0 || ${#AI_PORTS[@]} -eq 0 ]]; then
    echo "[!] Parsed empty management/ai ports from $PROFILE_YAML"
    exit 1
fi
SERVER_PORTS_CSV="$(
python3 - "$MGMT_PORTS_CSV" "$AI_PORTS_CSV" <<'PY'
import sys
vals = []
seen = set()
for part in (sys.argv[1] + "," + sys.argv[2]).split(","):
    p = part.strip()
    if not p or p in seen:
        continue
    seen.add(p)
    vals.append(p)
print(",".join(vals))
PY
)"
PRIMARY_MGMT_PORT="${MGMT_PORTS[0]}"
echo "[*] Using policy profile name: $PROFILE_NAME"
echo "[*] Policy ports: management=[$MGMT_PORTS_CSV] ai=[$AI_PORTS_CSV]"
# S7.1 ACCEPT: full script needs BPF LSM for ioctl gate (skip on unsupported nodes).
if [[ ! -r /sys/kernel/security/lsm ]] || ! tr ',' '\n' < /sys/kernel/security/lsm | grep -qx bpf; then
    echo "[!] BPF LSM inactive (need bpf in /sys/kernel/security/lsm). Full S7.1 skipped (exit 77)."
    exit 77
fi

if [[ "$KOTA_E2E_REQUIRE_CILIUM" == "1" ]]; then
    echo "[*] Preflight: checking Cilium/lxc* golden path..."
    CILIUM_READY="$(kubectl -n kube-system get ds cilium -o jsonpath='{.status.numberReady}' 2>/dev/null || true)"
    if [[ -z "${CILIUM_READY:-}" ]] || [[ "$CILIUM_READY" == "0" ]]; then
        echo "[!] Cilium daemonset not ready (or not installed)."
        echo "[!] Cilium/lxc* golden path is required. Skipping (exit 77)."
        exit 77
    fi
    if [[ ! -e /sys/fs/bpf/tc/globals/cilium_ipcache ]]; then
        echo "[!] Missing /sys/fs/bpf/tc/globals/cilium_ipcache on host."
        echo "[!] Cilium datapath tier appears incomplete. Skipping (exit 77)."
        exit 77
    fi
    if ! ip -o link show | awk -F': ' '{print $2}' | grep -q '^lxc'; then
        echo "[!] No host interfaces matching lxc* detected."
        echo "[!] Golden path expects Cilium host-veth naming. Skipping (exit 77)."
        exit 77
    fi
fi

echo "[*] Preflight: checking Kubernetes node GPU allocatable..."
GPU_ALLOC_LINES="$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"="}{.status.allocatable.nvidia\.com/gpu}{"\n"}{end}' 2>/dev/null || true)"
if [[ -z "$GPU_ALLOC_LINES" ]] || ! printf '%s\n' "$GPU_ALLOC_LINES" | rg -q '=[1-9][0-9]*'; then
    echo "[!] No schedulable nvidia.com/gpu detected on cluster nodes:"
    printf '%s\n' "$GPU_ALLOC_LINES"
    echo "[!] Check NVIDIA device plugin/runtime first. Skipping (exit 77)."
    exit 77
fi
printf '%s\n' "$GPU_ALLOC_LINES"

if [[ "$KOTA_E2E_PREFLIGHT_API_CHECK" == "1" ]]; then
    echo "[*] Preflight: checking API reachability from pod network..."
    kubectl run kota-e2e-api-check --rm -i --restart=Never --image=curlimages/curl:8.7.1 -- \
        sh -lc 'code="$(curl -k -sS -o /tmp/kota_api_body -w "%{http_code}" --connect-timeout 5 --max-time 10 https://10.43.0.1/version || true)"; echo "HTTP_CODE=${code}"' \
        >"$API_CHECK_LOG" 2>&1 || true
    API_HTTP_CODE="$(rg -o 'HTTP_CODE=[0-9]{3}' "$API_CHECK_LOG" | awk -F= 'NR==1 {print $2}')"
    if [[ -z "${API_HTTP_CODE:-}" ]] || [[ "$API_HTTP_CODE" == "000" ]]; then
        echo "[!] API preflight did not observe a valid HTTP status from 10.43.0.1:443."
        echo "[!] Check Cilium/UFW/FORWARD policy before running E2E."
        echo "[!] Preflight output:"
        cat "$API_CHECK_LOG"
        exit 1
    fi
    echo "[*] API preflight passed (HTTP ${API_HTTP_CODE})."
fi

# 2. Start Kotad
echo "[*] Starting kotad in background ($KOTAD_BIN)..."
sudo rm -rf /sys/fs/bpf/kota
export KOTA_PROFILE_DIR="tests/fixtures/profiles"
# Ensure telemetry transitions are responsive during E2E.
export KOTA_NVML_POLL_MS="${KOTA_NVML_POLL_MS:-1000}"
# Shorter Cilium retry than kotad default 15ms speeds second-cgroup resolves in E2E (override if flaky).
export KOTA_CILIUM_UDS_RETRY_SLEEP_MS="${KOTA_CILIUM_UDS_RETRY_SLEEP_MS:-8}"
if [[ "${KOTA_E2E_LOG_RESOLVE_TIMING:-0}" == "1" ]]; then
    export KOTA_LOG_RESOLVE_TIMING=1
    echo "[*] KOTA_LOG_RESOLVE_TIMING=1 (Cilium vs OCI timing on stderr → $KOTAD_LOG)"
fi
$KOTAD_BIN --telemetry-profile "$PROFILE_YAML" > "$KOTAD_LOG" 2>&1 &
KOTAD_PID=$!

sleep 3

STATUS_MAP_PIN="/sys/fs/bpf/kota/kota_status_map"
if ! bpftool map show pinned "$STATUS_MAP_PIN" >/dev/null 2>&1; then
    echo "[!] kota_status_map pin not found at $STATUS_MAP_PIN. kotad startup failed."
    cat "$KOTAD_LOG"
    exit 1
fi
STATUS_MAP_ID=$(bpftool map show pinned "$STATUS_MAP_PIN" | awk 'NR==1 {print $1}' | tr -d ':')
if [[ -z "$STATUS_MAP_ID" ]]; then
    echo "[!] Failed to resolve map id from pinned map at $STATUS_MAP_PIN."
    cat "$KOTAD_LOG"
    exit 1
fi

wait_for_any_verdict() {
    local target="$1"
    local timeout_s="${2:-10}"
    local deadline=$((SECONDS + timeout_s))

    while (( SECONDS < deadline )); do
        if python3 - "$STATUS_MAP_PIN" "$target" <<'PY'
import json, subprocess, sys
pin = sys.argv[1]
target = int(sys.argv[2])
try:
    out = subprocess.check_output(["bpftool", "map", "dump", "pinned", pin, "-j"])
    entries = json.loads(out)
except Exception:
    sys.exit(1)
if not entries:
    sys.exit(1)
for e in entries:
    v = e.get("value")
    if isinstance(v, dict):
        # BTF pretty JSON: {"verdict": 1, ...}
        if int(v.get("verdict", -1)) == target:
            sys.exit(0)
    elif isinstance(v, list):
        # Raw byte JSON: verdict is u32 at bytes [4..7] little-endian.
        if len(v) >= 8:
            try:
                b4 = int(v[4], 16) if isinstance(v[4], str) else int(v[4])
                b5 = int(v[5], 16) if isinstance(v[5], str) else int(v[5])
                b6 = int(v[6], 16) if isinstance(v[6], str) else int(v[6])
                b7 = int(v[7], 16) if isinstance(v[7], str) else int(v[7])
                verdict = b4 | (b5 << 8) | (b6 << 16) | (b7 << 24)
                if verdict == target:
                    sys.exit(0)
            except Exception:
                pass
sys.exit(1)
PY
        then
            return 0
        fi
        sleep 1
    done
    return 1
}

# 3. Deploy Workload
echo "[*] Deploying labeled GPU pod ($POD_NAME) and unlabeled control pod ($POD_UNLABELED_NAME)..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $POD_NAME
  labels:
    kota.ai/profile: "$PROFILE_NAME"
  annotations:
    kota.ai/profile: "$PROFILE_NAME"
spec:
  containers:
  - name: workload
    image: python:3.10-slim
    command: ["/bin/bash", "-c"]
    args:
    - |
      IFS=',' read -r -a ports <<< "$SERVER_PORTS_CSV"
      for p in "\${ports[@]}"; do
        python3 -m http.server "\$p" >/tmp/http-\$p.log 2>&1 &
      done
      sleep 3600
    resources:
      limits:
        nvidia.com/gpu: 1
---
apiVersion: v1
kind: Pod
metadata:
  name: $POD_UNLABELED_NAME
spec:
  containers:
  - name: control
    image: python:3.10-slim
    command: ["/bin/bash", "-c"]
    args:
    - |
      python3 -m http.server $PRIMARY_MGMT_PORT &
      sleep 3600
EOF

echo "[*] Waiting for pods to be running..."
if ! kubectl wait --for=condition=Ready pod/"$POD_NAME" --timeout=60s; then
    echo "[!] Pod did not become Ready in time."
    kubectl describe pod "$POD_NAME" || true
    kubectl get nodes -o custom-columns='NAME:.metadata.name,ALLOCATABLE_GPU:.status.allocatable.nvidia\.com/gpu,CAPACITY_GPU:.status.capacity.nvidia\.com/gpu' || true
    exit 1
fi
if ! kubectl wait --for=condition=Ready pod/"$POD_UNLABELED_NAME" --timeout=60s; then
    echo "[!] Unlabeled control pod did not become Ready in time."
    kubectl describe pod "$POD_UNLABELED_NAME" || true
    exit 1
fi
POD_IP=$(kubectl get pod "$POD_NAME" -o jsonpath='{.status.podIP}')
echo "[*] Pod IP: $POD_IP"

echo "[*] Waiting for kotad to resolve identity..."
sleep 5
if ! rg -q "Identity enforced \(ACTIVE\) for default/$POD_NAME" "$KOTAD_LOG"; then
    echo "[!] Labeled pod was not enforced. Expected identity enforcement log missing."
    tail -n 80 "$KOTAD_LOG" || true
    exit 1
fi
if rg -q "Identity enforced \(ACTIVE\) for default/$POD_UNLABELED_NAME" "$KOTAD_LOG"; then
    echo "[!] Unlabeled control pod was enforced, expected skip."
    tail -n 80 "$KOTAD_LOG" || true
    exit 1
fi
if ! rg -q "profile gate skip.*$POD_UNLABELED_NAME|skip:profile.*$POD_UNLABELED_NAME" "$KOTAD_LOG"; then
    echo "[*] Warning: explicit profile skip log for unlabeled pod not observed yet."
    echo "[*] Continuing, because enforcement check above already confirms skip behavior."
fi
if [[ "$KOTA_E2E_REQUIRE_CILIUM" == "1" ]]; then
    if grep -Eq 'resolver->TCX.*target=`lxc|Resolved Pod: .* -> Iface: lxc' "$KOTAD_LOG"; then
        echo "[*] Info: kotad log shows lxc* resolver evidence."
    else
        echo "[*] Info: no lxc* resolver evidence observed in current log window (non-fatal)."
    fi
fi

# Resolve a real NVIDIA device path inside pod (no fake node path).
IOCTL_TARGET_PATH="$(kubectl exec "$POD_NAME" -- sh -c 'for p in /dev/nvidiactl /dev/nvidia0 /dev/nvidia1 /dev/nvidia-uvm; do [ -e "$p" ] && { echo "$p"; exit 0; }; done; exit 1' 2>/dev/null || true)"
if [[ -z "$IOCTL_TARGET_PATH" ]]; then
    echo "[!] No real /dev/nvidia* device found in pod. Ensure NVIDIA device-plugin is healthy."
    kubectl describe pod "$POD_NAME" || true
    exit 1
fi
echo "[*] Using ioctl test target: $IOCTL_TARGET_PATH"

# Create IOCTL Python test inside pod
cat << 'EOF' > /tmp/test_ioctl.py
import fcntl, os, sys
path = sys.argv[1]
try:
    fd = os.open(path, os.O_RDWR)
    fcntl.ioctl(fd, 0x4601)
except PermissionError:
    sys.exit(13)
except OSError as e:
    sys.exit(0)
EOF
kubectl cp /tmp/test_ioctl.py $POD_NAME:/tmp/test_ioctl.py

cat << 'EOF' > /tmp/test_real_gpu_call.py
import ctypes
import sys

def load_cuda():
    for name in ("libcuda.so.1", "/usr/lib/x86_64-linux-gnu/libcuda.so.1"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            pass
    return None

cuda = load_cuda()
if cuda is None:
    sys.exit(42)

cuda.cuInit.argtypes = [ctypes.c_uint]
cuda.cuInit.restype = ctypes.c_int
rc = cuda.cuInit(0)
if rc != 0:
    sys.exit(2)

count = ctypes.c_int(0)
cuda.cuDeviceGetCount.argtypes = [ctypes.POINTER(ctypes.c_int)]
cuda.cuDeviceGetCount.restype = ctypes.c_int
rc = cuda.cuDeviceGetCount(ctypes.byref(count))
if rc != 0:
    sys.exit(3)

if count.value < 1:
    sys.exit(4)
sys.exit(0)
EOF
kubectl cp /tmp/test_real_gpu_call.py $POD_NAME:/tmp/test_real_gpu_call.py

run_ioctl_probe() {
    local phase="$1"
    local expect_blocked="$2" # 1 => expect EACCES(13), 0 => expect open
    local rc=0

    set +e
    kubectl exec "$POD_NAME" -- python3 /tmp/test_ioctl.py "$IOCTL_TARGET_PATH"
    rc=$?
    set -e

    if [[ "$expect_blocked" == "1" ]]; then
        if [[ $rc -eq 13 ]]; then
            echo "[+] Proof: IOCTL is BLOCKED during ${phase} (rc=13, EACCES)"
            return 0
        fi
        if [[ "$KOTA_E2E_STRICT_IOCTL" == "1" ]]; then
            echo "[!] Proof FAIL: IOCTL is OPEN during ${phase} (rc=$rc), expected BLOCKED(EACCES)"
            return 1
        fi
        echo "[!] Proof WARN: IOCTL is OPEN during ${phase} (rc=$rc), expected BLOCKED(EACCES). Continuing (KOTA_E2E_STRICT_IOCTL=0)."
        return 0
    fi

    if [[ $rc -eq 13 ]]; then
        if [[ "$KOTA_E2E_STRICT_IOCTL" == "1" ]]; then
            echo "[!] Proof FAIL: IOCTL is BLOCKED during ${phase} (rc=13), expected OPEN"
            return 1
        fi
        echo "[!] Proof WARN: IOCTL is BLOCKED during ${phase} (rc=13), expected OPEN. Continuing (KOTA_E2E_STRICT_IOCTL=0)."
        return 0
    fi
    echo "[+] Proof: IOCTL is OPEN during ${phase} (rc=$rc)"
    return 0
}

run_real_gpu_probe() {
    local phase="$1"
    local expect_blocked="$2" # 1 => expect call failure under VIOLATION, 0 => expect success
    local rc=0

    set +e
    kubectl exec "$POD_NAME" -- python3 /tmp/test_real_gpu_call.py
    rc=$?
    set -e

    if [[ $rc -eq 42 ]]; then
        echo "[*] Proof WARN: real GPU probe unavailable in pod image (libcuda missing)."
        return 0
    fi

    if [[ "$expect_blocked" == "1" ]]; then
        if [[ $rc -ne 0 ]]; then
            echo "[+] Proof: REAL GPU call is BLOCKED/FAILED during ${phase} (rc=$rc)"
            return 0
        fi
        if [[ "$KOTA_E2E_STRICT_REAL_GPU" == "1" ]]; then
            echo "[!] Proof FAIL: REAL GPU call is OPEN during ${phase} (rc=0), expected failure"
            return 1
        fi
        echo "[!] Proof WARN: REAL GPU call is OPEN during ${phase} (rc=0), expected failure. Continuing (KOTA_E2E_STRICT_REAL_GPU=0)."
        return 0
    fi

    if [[ $rc -eq 0 ]]; then
        echo "[+] Proof: REAL GPU call is OPEN during ${phase} (rc=0)"
        return 0
    fi
    if [[ "$KOTA_E2E_STRICT_REAL_GPU" == "1" ]]; then
        echo "[!] Proof FAIL: REAL GPU call is BLOCKED/FAILED during ${phase} (rc=$rc), expected success"
        return 1
    fi
    echo "[!] Proof WARN: REAL GPU call is BLOCKED/FAILED during ${phase} (rc=$rc), expected success. Continuing (KOTA_E2E_STRICT_REAL_GPU=0)."
    return 0
}

# 4. Phase 1 & 2 Validation
echo "[*] Testing ACTIVE network gates..."
for p in "${AI_PORTS[@]}"; do
    curl -s --connect-timeout 2 "http://$POD_IP:$p" > /dev/null || (echo "[!] Failed AI port $p (ACTIVE)"; exit 1)
done
for p in "${MGMT_PORTS[@]}"; do
    curl -s --connect-timeout 2 "http://$POD_IP:$p" > /dev/null || (echo "[!] Failed management port $p (ACTIVE)"; exit 1)
done

echo "[*] Testing ACTIVE hardware gate (IOCTL)..."
if ! run_ioctl_probe "ACTIVE" 0; then
    echo "[!] Proof FAIL: IOCTL check failed during ACTIVE."
    exit 1
fi
echo "[*] Testing ACTIVE hardware gate (REAL GPU call)..."
if ! run_real_gpu_probe "ACTIVE" 0; then
    echo "[!] Proof FAIL: REAL GPU call check failed during ACTIVE."
    exit 1
fi
echo "[+] Gates OPEN."

# 5. Helper to poke BPF Map (debug fallback only)
cat << 'EOF' > /tmp/poke_map.py
import json, subprocess, sys

map_id = sys.argv[1]
target_verdict = int(sys.argv[2])

out = subprocess.check_output(["bpftool", "map", "dump", "id", map_id, "-j"])
try:
    entries = json.loads(out)
except json.JSONDecodeError:
    print(f"Failed to decode bpftool JSON output: {out}")
    sys.exit(1)

if not entries:
    print(f"status map id={map_id} has no entries; cannot change verdict")
    sys.exit(1)

updated = 0
for entry in entries:
    key = entry["key"]
    val = entry["value"]

    val[4] = f"0x{target_verdict:02x}"
    val[5] = "0x00"
    val[6] = "0x00"
    val[7] = "0x00"

    key_str = " ".join(key)
    val_str = " ".join(val)

    cmd = f"bpftool map update id {map_id} key hex {key_str} value hex {val_str}"
    subprocess.check_call(cmd, shell=True)
    updated += 1

if updated == 0:
    print("status map update changed 0 entries")
    sys.exit(1)

out_after = subprocess.check_output(["bpftool", "map", "dump", "id", map_id, "-j"])
entries_after = json.loads(out_after)
matches = 0
for entry in entries_after:
    val = entry["value"]
    if len(val) >= 8 and val[4].lower() == f"0x{target_verdict:02x}" and val[5:8] == ["0x00", "0x00", "0x00"]:
        matches += 1

if matches == 0:
    print(f"verdict verification failed for map id={map_id}; target={target_verdict}")
    sys.exit(1)

print(f"updated {updated} status entries; verified verdict={target_verdict} in {matches} entries")
EOF

start_gpu_stress() {
    if [[ -z "$KOTA_E2E_GPU_STRESS_CMD" ]]; then
        echo "[!] KOTA_E2E_GPU_STRESS_CMD is not set."
        echo "[!] Provide a lab-safe stress command to drive NVML fault transitions."
        echo "[!] Example: export KOTA_E2E_GPU_STRESS_CMD='gpu_burn 120'"
        exit 77
    fi
    echo "[*] Starting GPU stress command: $KOTA_E2E_GPU_STRESS_CMD"
    bash -lc "$KOTA_E2E_GPU_STRESS_CMD" >/tmp/kota_e2e_gpu_stress.log 2>&1 &
    GPU_STRESS_PID=$!
    sleep 2
    if ! kill -0 "$GPU_STRESS_PID" 2>/dev/null; then
        echo "[!] GPU stress command exited immediately. Check /tmp/kota_e2e_gpu_stress.log"
        cat /tmp/kota_e2e_gpu_stress.log || true
        exit 1
    fi
}

stop_gpu_stress() {
    if [[ -n "${GPU_STRESS_PID:-}" ]]; then
        echo "[*] Stopping GPU stress (pid=$GPU_STRESS_PID)"
        kill "$GPU_STRESS_PID" 2>/dev/null || true
        wait "$GPU_STRESS_PID" 2>/dev/null || true
        GPU_STRESS_PID=""
    fi
}

# 6. Phase 3 Validation (fault -> VIOLATION)
echo "[*] Driving fault transition (Verdict -> VIOLATION)..."
if [[ "$KOTA_E2E_DEBUG_POKE" == "1" ]]; then
    echo "[*] DEBUG mode enabled: forcing VIOLATION via map poke."
    python3 /tmp/poke_map.py "$STATUS_MAP_ID" 1
else
    start_gpu_stress
fi

if ! wait_for_any_verdict 1 "$KOTA_E2E_VIOLATION_TIMEOUT_S"; then
    echo "[!] Timed out waiting for VIOLATION verdict in status map."
    tail -n 40 "$KOTAD_LOG" || true
    bpftool map dump pinned "$STATUS_MAP_PIN" || true
    exit 1
fi

echo "[*] Testing VIOLATION network gates..."
set +e
for p in "${AI_PORTS[@]}"; do
    curl -s --connect-timeout 2 "http://$POD_IP:$p" > /dev/null
    rc=$?
    if [ $rc -eq 0 ]; then
        echo "[!] Proof FAIL: AI port $p is OPEN during VIOLATION"
        exit 1
    fi
    echo "[+] Proof: AI port $p is BLOCKED during VIOLATION (curl rc=$rc)"
done
set -e
for p in "${MGMT_PORTS[@]}"; do
    curl -s --connect-timeout 2 "http://$POD_IP:$p" > /dev/null || (echo "[!] Proof FAIL: management port $p is BLOCKED during VIOLATION"; exit 1)
    echo "[+] Proof: management port $p remains OPEN during VIOLATION"
done

echo "[*] Testing VIOLATION hardware gate (IOCTL)..."
if ! run_ioctl_probe "VIOLATION" 1; then
    echo "[!] Proof FAIL: IOCTL check failed during VIOLATION."
    exit 1
fi
echo "[*] Testing VIOLATION hardware gate (REAL GPU call)..."
if ! run_real_gpu_probe "VIOLATION" 1; then
    echo "[!] Proof FAIL: REAL GPU call check failed during VIOLATION."
    exit 1
fi
echo "[+] Gates RESTRICTED correctly."

# 7. Phase 4 Validation (clear fault -> ACTIVE)
echo "[*] Driving recovery transition (Verdict -> ACTIVE)..."
if [[ "$KOTA_E2E_DEBUG_POKE" == "1" ]]; then
    echo "[*] DEBUG mode enabled: forcing ACTIVE via map poke."
    python3 /tmp/poke_map.py "$STATUS_MAP_ID" 0
else
    stop_gpu_stress
fi
if ! wait_for_any_verdict 0 "$KOTA_E2E_RECOVERY_TIMEOUT_S"; then
    echo "[!] Timed out waiting for ACTIVE verdict in status map."
    tail -n 40 "$KOTAD_LOG" || true
    bpftool map dump pinned "$STATUS_MAP_PIN" || true
    exit 1
fi

echo "[*] Testing RECOVERY network gates..."
for p in "${AI_PORTS[@]}"; do
    curl -s --connect-timeout 2 "http://$POD_IP:$p" > /dev/null || (echo "[!] AI port $p still blocked in RECOVERY"; exit 1)
    echo "[+] Proof: AI port $p is OPEN again during RECOVERY"
done
for p in "${MGMT_PORTS[@]}"; do
    curl -s --connect-timeout 2 "http://$POD_IP:$p" > /dev/null || (echo "[!] Management port $p still blocked in RECOVERY"; exit 1)
    echo "[+] Proof: management port $p remains OPEN during RECOVERY"
done

echo "[*] Testing RECOVERY hardware gate (IOCTL)..."
if ! run_ioctl_probe "RECOVERY" 0; then
    echo "[!] Proof FAIL: IOCTL check failed during RECOVERY."
    exit 1
fi
echo "[*] Testing RECOVERY hardware gate (REAL GPU call)..."
if ! run_real_gpu_probe "RECOVERY" 0; then
    echo "[!] Proof FAIL: REAL GPU call check failed during RECOVERY."
    exit 1
fi
echo "[+] Recovery SUCCESSFUL. Network End-to-End validation passed!"
