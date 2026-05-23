## Setup for demo

```bash
cd /path/to/KOTA

# 1) Build local image (already done if unchanged)
docker build -t kota-image-moderation:latest tests/apps/image-moderation-api

# 2) Import Docker image into k3s containerd (no registry push)
docker save kota-image-moderation:latest | sudo k3s ctr images import -

# See it
docker ps -a | rg kota-image-moderation

# Stop and delete
docker stop kota-image-moderation
docker rm kota-image-moderation

# 3) Deploy manifest
kubectl apply -f tests/apps/image-moderation-api/k8s/image-moderation-demo.yaml

# 4) Wait for pod ready
kubectl wait --for=condition=Ready pod -l app=kota-image-moderation -n kota-demo --timeout=180s

# 5) Forward both ports from service
kubectl port-forward svc/kota-image-moderation 8000:8000 2000:2000 -n kota-demo
```

If `kubectl port-forward` exits (pod/service restart, network hiccup), use auto-retry:

```bash
while true; do
  kubectl port-forward svc/kota-image-moderation 8000:8000 2000:2000 -n kota-demo
  echo "[port-forward] disconnected; retrying in 2s..."
  sleep 2
done
```

## Access from a GUI VM or remote laptop (browser)

The demo **HTML** is served on the **inference** port. The page loads **admin** via JavaScript using the **same hostname** as the page and port **`ADMIN_BROWSER_PORT`** (manifest default **`32000`**, matching the Service **admin** `nodePort`). So the browser must reach **both** published ports—**not** only `8000`/`2000` unless you change the Deployment env and rebuild.

### A — GUI VM on the **same LAN** as the k3s node (simplest)

1. On the **k3s host**, get the address other machines should use:

   ```bash
   kubectl get nodes -o wide
   ```

   Use **`INTERNAL-IP`** (or a DNS name that resolves to it) as **`NODE_IP`**.

2. On the **GUI VM**, open a browser:

   - **Inference / UI:** `http://<NODE_IP>:30800/`
   - **Admin** (opened automatically from the UI): `http://<NODE_IP>:32000/admin`

3. If the connection times out, open the ports on the node firewall (example **ufw**):

   ```bash
   sudo ufw allow 30800/tcp comment 'kota-demo inference NodePort'
   sudo ufw allow 32000/tcp comment 'kota-demo admin NodePort'
   sudo ufw reload
   ```

   (`30800` / `32000` match `tests/apps/image-moderation-api/k8s/image-moderation-demo.yaml`; if you change `nodePort` values, update **`ADMIN_BROWSER_PORT`** in the Deployment and rebuild/re-import the image.)

### B — Browser only reaches the lab via **SSH** (jump host = k3s node)

On the **GUI VM**, forward **both** NodePorts to the demo server (replace `user` / `demo-server`):

```bash
ssh -N \
  -L 30800:127.0.0.1:30800 \
  -L 32000:127.0.0.1:32000 \
  user@demo-server
```

Leave that session connected, then in the browser on the **GUI VM**:

- `http://127.0.0.1:30800/`

Admin calls go to `http://127.0.0.1:32000/admin` via the second forward.

### C — You use **`kubectl port-forward`** on the server (not NodePort)

The UI still requests **admin on port `32000`** by default. From a remote machine you typically need **three** forwards if `kubectl port-forward` is bound on the server’s loopback only:

```bash
# On GUI VM — demo-server runs: kubectl port-forward ... 8000:8000 2000:2000
ssh -N \
  -L 8000:127.0.0.1:8000 \
  -L 2000:127.0.0.1:2000 \
  -L 32000:127.0.0.1:32000 \
  user@demo-server
```

Then open `http://127.0.0.1:8000/`. For **KOTA enforcement** demos, prefer **NodePort (A/B)** so traffic matches the `lxc*` dataplane path; see the next section.

### Where to run `kubectl port-forward` (demo app)

`kubectl port-forward` must run on a machine that has a working **kubeconfig** for the cluster (almost always the **k3s demo host**), not inside the browser VM unless you copied kubeconfig and connectivity there.

1. **On the demo server** (SSH session or `tmux`/`screen`), start the forward and leave it running:

   ```bash
   cd /path/to/KOTA
   kubectl port-forward svc/kota-image-moderation 8000:8000 2000:2000 -n kota-demo
   ```

   That binds **`127.0.0.1:8000`** and **`127.0.0.1:2000`** on the **server** (unless you pass `--address`).

2. **On the GUI VM**, open an **SSH local tunnel** into those listeners (section **C** above). The browser on the GUI VM then uses **`http://127.0.0.1:8000/`** etc.

You do **not** “turn on port-forward in the GUI” as a separate product: the GUI only needs **SSH `-L`** (or a VPN) so `127.0.0.1` on the GUI VM reaches the server’s forwarded ports.

### D — Grafana (and optional Prometheus) from a GUI VM

Start the stack on the **demo server** first (`./scripts/kota-metrics-stack.sh start`). **`kota-grafana`** publishes host port **`3000`** (`-p 3000:3000` in `scripts/kota-metrics-stack.sh`).

**Same LAN as the demo host**

- Grafana: **`http://<NODE_IP>:3000`**
- If the page does not load, allow **`3000/tcp`** on the server firewall (same idea as NodePorts for the demo app).

**Browser only reaches the lab via SSH**

On the **GUI VM**, in a terminal (leave the session open; **`-N`** = no remote shell, tunnels only):

```bash
ssh -N -L 3000:127.0.0.1:3000 user@demo-server
```

Then on the **GUI VM** browser: **`http://127.0.0.1:3000`**

Inside Grafana, the Prometheus datasource stays **`http://kota-prometheus:9090`** (Docker network on the server). You do **not** point the browser at Prometheus for normal dashboard use—Grafana’s backend queries Prometheus over Docker.

**One SSH session: demo NodePorts + Grafana**

After **`kota-metrics-stack.sh start`** on the server:

```bash
ssh -N \
  -L 30800:127.0.0.1:30800 \
  -L 32000:127.0.0.1:32000 \
  -L 3000:127.0.0.1:3000 \
  user@demo-server
```

Then on the GUI VM:

| What | URL |
| --- | --- |
| Image moderation UI | `http://127.0.0.1:30800/` |
| Grafana | `http://127.0.0.1:3000` |

**Optional — Prometheus UI in the browser on the GUI VM** (Explore raw queries; not required for Grafana):

```bash
ssh -N -L 9090:127.0.0.1:9090 user@demo-server
```

→ **`http://127.0.0.1:9090`** (see the metrics section table for datasource vs direct UI).

## curl on the server: Service ClusterIP vs `port-forward` (enforcement path)

KOTA’s TCX **Scalpel** is intended for traffic that crosses the **CNI / `lxc*`** path. **`kubectl port-forward`** usually forwards from the **node** to the **Pod** in a way that **does not** match the same host-ingress story as a client hitting **Service ClusterIP**, **NodePort** on the node, or a **Pod IP** from the node. Rehearse paths below during **ACTIVE** vs **NVML VIOLATION** (see `docs/flow.md`).

**How to read `curl`:** `-m` is **seconds** (e.g. `-m 1` = one second, not 1 ms). With a **short** max time, a **dropped or hung AI port** usually shows as **`curl: (28) Operation timed out`** (exit **28**) — you never get an HTTP status line, so that is a **network/dataplane** symptom (TCX, routing, firewall), **not** “the app returned a CUDA error in JSON.” If you **do** get **`HTTP/... 5xx`** and JSON with **`detail`**, **`request_reached_application: true`**, and **`failure_domain`** (e.g. `gpu_runtime`), the POST **entered the demo pod**: that proves **different** symptom class from **silent network drop**. Use **`demo_audience_note`** in that JSON when presenting so viewers do not confuse **CUDA/driver plumbing** failures with **`kotad` ACTIVE vs VIOLATION** policy demos.

Set once (adjust image path; manifest uses inference `nodePort` **30800** and admin **32000** — `kubectl` picks up whatever is allocated):

```bash
cd /path/to/KOTA
export NS=kota-demo
export SVC=kota-image-moderation
export IMG="$PWD/tests/manual/dog.jpg"
# Short client timeout for AI POST so blocks look like fast timeouts, not a hang (float seconds).
export CURL_MAXTIME_AI="${CURL_MAXTIME_AI:-1}"

CLUSTER_IP=$(kubectl get svc -n "$NS" "$SVC" -o jsonpath='{.spec.clusterIP}{"\n"}')
NODE_PORT_AI=$(kubectl get svc -n "$NS" "$SVC" -o jsonpath='{.spec.ports[?(@.name=="inference")].nodePort}{"\n"}')
NODE_PORT_ADMIN=$(kubectl get svc -n "$NS" "$SVC" -o jsonpath='{.spec.ports[?(@.name=="admin")].nodePort}{"\n"}')
POD_IP=$(kubectl get pod -n "$NS" -l app=kota-image-moderation -o jsonpath='{.items[0].status.podIP}{"\n"}')
# Same host as k3s / browser on that host: default loopback; multi-node: set NODE_IP to a node InternalIP (`kubectl get nodes -o wide`).
export NODE_IP="${NODE_IP:-127.0.0.1}"

echo "ClusterIP=${CLUSTER_IP}"
echo "NodePort  AI=${NODE_PORT_AI}  admin=${NODE_PORT_ADMIN}  (use http://${NODE_IP}:<port>)"
echo "Pod IP=${POD_IP}"
```

Optional: print HTTP code and total time after the body (still obeys `-m`):

```bash
kota_curl_infer() {
  local url="$1"
  curl -m "$CURL_MAXTIME_AI" -sS -F "image=@${IMG}" "$url" \
    -w "\n# infer: http_code=%{http_code} time_total_sec=%{time_total}\n" \
    || { echo >&2 "# infer: curl exit=$? (28 = timed out → treat as network path, no HTTP reply in CURL_MAXTIME_AI=${CURL_MAXTIME_AI}s)"; return 1; }
}
```

### A — Service ClusterIP (typical dataplane path from the node netns)

```bash
curl -m "$CURL_MAXTIME_AI" -sS -F "image=@${IMG}" "http://${CLUSTER_IP}:8000/process"
curl -m "$CURL_MAXTIME_AI" -sS "http://${CLUSTER_IP}:2000/admin"
```

### B — NodePort on the node (**browser / LAN friendly**)

```bash
curl -m "$CURL_MAXTIME_AI" -sS -F "image=@${IMG}" "http://${NODE_IP}:${NODE_PORT_AI}/process"
curl -m "$CURL_MAXTIME_AI" -sS "http://${NODE_IP}:${NODE_PORT_ADMIN}/admin"
```

The demo **HTML** calls admin at `http://<same-host>:<ADMIN_BROWSER_PORT>/admin` (not container port `2000`). The manifest sets **`ADMIN_BROWSER_PORT` = `32000`** to match the Service `admin` **nodePort**. If you change **nodePort** values in `image-moderation-demo.yaml`, update **both** the Service and **`ADMIN_BROWSER_PORT`**, then rebuild/re-import the image and restart the pod.

**Optional (`INFER_BROWSER_TIMEOUT_MS`):** The demo UI can apply a browser-side cap on **`/process`** (`AbortSignal.timeout`). Leave unset (**0**) so cold GPU/load is not aborted. After the model has warmed once, set e.g. **`INFER_BROWSER_TIMEOUT_MS=1200`** in the Deployment env **only if** you want the browser to classify slow stalls similarly to **`curl -m`** (timeouts show as explicit **TimeoutError** styling in the banner).

### C — Direct to Pod IP from the node (optional second hop)

```bash
curl -m "$CURL_MAXTIME_AI" -sS -F "image=@${IMG}" "http://${POD_IP}:8000/process"
curl -m "$CURL_MAXTIME_AI" -sS "http://${POD_IP}:2000/admin"
```

### D — Through `kubectl port-forward` to localhost (compare when tunnel is **on**)

In another terminal, keep port-forward running (`8000`/`2000`), then:

```bash
curl -sS -F "image=@${IMG}" http://127.0.0.1:8000/process
curl -sS http://127.0.0.1:2000/admin
```

**What to compare:** run **A**, **B**, or **C** with port-forward **off**, then repeat with port-forward **on** for **D** during the same **kotad** verdict window (`sudo ./build/kotactl status`). AI path (`8000` / NodePort inference) vs admin (`2000` / NodePort admin) behavior should follow your profile (`tests/fixtures/profiles/nvml_fault_injection_lab.yaml`: `ai_ports` vs `management_ports`).

Automated in-cluster checks (no port-forward): `tests/manual/e2e_network_gpu.sh`.

## kotad / kotactl policy registration (profile-bound pod)

```bash
cd /path/to/KOTA

# 6) Make sure kotad control plane is running
sudo systemctl status kotad --no-pager

# 7) Register policy/profile in kotad policy store
# NOTE: kotad socket is root-owned (/run/kota/kotad.sock), so use sudo.
sudo ./build/kotactl apply -f tests/fixtures/profiles/nvml_fault_injection_lab.yaml

# 8) Verify pod is created with matching policy label from manifest
kubectl get deploy -n kota-demo kota-image-moderation -o jsonpath='{.spec.template.metadata.labels.kota\.ai/profile}{"\n"}'
kubectl get pod -n kota-demo -l 'kota.ai/profile=NVML-Lab-Fault-Injection'

# 9) Verify workload is managed (not profile_id=0 unmanaged path)
sudo ./build/kotactl status
```

## kotad logs (what “profile gate skip” means)

If you see:

`PodResolver: profile gate skip ... oci runtime metadata has no kota.ai/profile`

that path read containerd task `config.json` and did not find `"kota.ai/profile"` there. Often it is an **unlabeled** pod (e.g. kube-system) or **pause** — not your demo workload. Confirm with `sudo ./build/kotactl status` that `kota-demo` pod shows the expected **PROFILE** and **ARMED**.

Optional: after your app pod is running, check that containerd state contains the key (path is k3s-specific):

`sudo rg 'kota\.ai/profile' /run/k3s/containerd/io.containerd.runtime.v2.task/k8s.io/ --glob config.json`

## metrics + grafana (OTLP -> collector -> prometheus -> grafana)

**One-shot stack (start / stop / status):**

```bash
cd /path/to/KOTA
./scripts/kota-metrics-stack.sh start    # creates kota-metrics, OTEL + Prometheus + Grafana, health-checks
./scripts/kota-metrics-stack.sh status
./scripts/kota-metrics-stack.sh stop     # removes containers + kota-metrics network (does not stop kotad/k8s)
```

Manual equivalents live in `scripts/kota-metrics-stack.sh` if you need to tune flags.

**After metrics stack is up — start kotad** (separate process; not part of the script):

```bash
cd /path/to/KOTA
sudo env OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
  KOTA_TELEMETRY_PROFILE=tests/fixtures/profiles/nvml_fault_injection_lab.yaml \
  ./build/kota/kotad
```

Optional smoke from the host:

```bash
curl -sSf http://127.0.0.1:9091/metrics | rg 'kota_|kotad_' | head -n 5
curl -sS 'http://127.0.0.1:9090/api/v1/query?query=kota_otel_startup_total'
```

Then in Grafana:

- URL: `http://<server-ip>:3000` on the LAN, or **`http://127.0.0.1:3000`** on the GUI VM after **`ssh -L 3000:127.0.0.1:3000`** (step-by-step: **D — Grafana** in the “Access from a GUI VM” section above).
- **Prometheus datasource URL (all on `kota-metrics`):** `http://kota-prometheus:9090`  
  **Do not** point Grafana’s Prometheus datasource at **`kota-otelcol:9091`**. That endpoint is **scrape-only** (`/metrics` text). Grafana’s Prometheus plugin calls **`/api/v1/query`** on a real Prometheus — without `kota-prometheus`, Save & Test fails and `docs/grafana/kota-demo.json` stays empty.

**Datasource “green” but dashboards show No data:** Save & test only checks Prometheus — **KOTA series appear only after `kotad` exports OTLP** into the collector (`OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318`). Without `kotad` running, Prometheus may be nearly empty. On the **demo server**:

```bash
curl -sS 'http://127.0.0.1:9090/api/v1/query?query=kota_otel_startup_total'
curl -sS 'http://127.0.0.1:9090/api/v1/query?query=kotad_uptime_seconds_count'
```

If those return empty `result`, start **`kotad`** with OTLP set (see above). In Grafana **Explore** → Prometheus, try **`kotad_uptime_seconds_sum`** or **`kota_nvml_gpu_temp_celsius_C_sum`**. Widen time range (**Last 6 hours**). On **import** `kota-demo.json`, pick your Prometheus datasource for **`ds_prometheus`**.

| Grafana | Metrics backend | Grafana “Prometheus” datasource URL |
| --- | --- | --- |
| **Docker (`kota-grafana`) on `kota-metrics`** | **`kota-prometheus`** scrapes **`kota-otelcol:9091`** | **`http://kota-prometheus:9090`** |
| **Native Grafana on demo host** | Prometheus Docker `-p 9090:9090` | `http://127.0.0.1:9090` |
| **GUI VM** | SSH `-L 9090:127.0.0.1:9090` to server | `http://127.0.0.1:9090` |

Smoke: Prometheus → OTel target is `UP`:

```bash
docker run --rm --network kota-metrics curlimages/curl:8.5.0 -sS --max-time 5 \
  'http://kota-prometheus:9090/api/v1/targets' | rg -o '"health":"[^"]*"'
```

If containers were created **without** `kota-metrics`, attach after `docker network create kota-metrics`:

```bash
docker network create kota-metrics 2>/dev/null || true
docker network connect kota-metrics kota-otelcol
docker network connect kota-metrics kota-prometheus
docker network connect kota-metrics kota-grafana
```

Then set Grafana Prometheus URL to **`http://kota-prometheus:9090`** and Save & test again.

- Datasource HTTP access: leave default **Server** (Grafana backend queries Prometheus).
- Import dashboard: **Dashboards → Import** → `docs/grafana/kota-demo.json` — if you imported an older copy, **delete the dashboard and import again** after pulling the repo (queries were updated for OTel→Prometheus metric names like `kota_nvml_gpu_temp_celsius_C_*` and `*_milliseconds_bucket`).

Demo verification mapping:

- `ACTIVE -> VIOLATION` transition: `kota_verdict_state`, `kota_verdict_transitions_total`
- GPU thermal trigger: `kota_nvml_gpu_temp_celsius_C_*` (histogram)
- Network enforcement drops: `kota_packets_dropped_total`, `kota_bytes_dropped_total` (only appear in Prometheus **after** kotad has recorded drop events — no traffic / no blocks → “No data” is normal)
- GPU ioctl/mmaps veto path: `kota_lsm_veto_events_total` (same — only when LSM veto fires)

**Inference still works while `kotactl` shows VIOLATION:** `kubectl port-forward` from the **node** often does **not** exercise the same host `lxc*` TCX path as traffic that crosses the CNI legs the demo enforces. Prefer an in-cluster client (e.g. `kubectl run curl --image=curlimages/curl` → pod IP:8000), **NodePort**, or direct access from another host to the **Service** / **Pod** IP to validate AI-path blocking; keep **:2000** admin on `management_ports` in your profile (`tests/fixtures/profiles/nvml_fault_injection_lab.yaml` includes **2000** for the dual-port story).