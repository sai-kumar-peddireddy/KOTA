from __future__ import annotations

import asyncio
import io
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from typing import Any

import torch
import torch.nn.functional as F
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse
from PIL import Image
from torchvision import models, transforms


@dataclass
class RuntimeState:
    started_at_monotonic: float
    started_at_utc: datetime
    version: str


class GpuImageModerator:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model: torch.nn.Module | None = None
        self._preprocess = None
        self._labels: list[str] = []

    def _init_model_locked(self) -> None:
        if self._model is not None:
            return
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA is unavailable; GPU-backed inference cannot start")

        try:
            weights = models.ResNet50_Weights.DEFAULT
            model = models.resnet50(weights=weights)
            self._labels = list(weights.meta.get("categories", []))
            self._preprocess = weights.transforms()
        except Exception:
            model = models.resnet50(weights=None)
            self._labels = [f"class_{i}" for i in range(1000)]
            self._preprocess = transforms.Compose(
                [
                    transforms.Resize(256),
                    transforms.CenterCrop(224),
                    transforms.ToTensor(),
                    transforms.Normalize(
                        mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]
                    ),
                ]
            )

        self._model = model.eval().to("cuda")

    def classify(self, image_bytes: bytes, topk: int = 5) -> list[dict[str, Any]]:
        with self._lock:
            self._init_model_locked()
            assert self._model is not None and self._preprocess is not None
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            tensor = self._preprocess(img).unsqueeze(0).to("cuda")
            with torch.inference_mode():
                logits = self._model(tensor)
                probs = F.softmax(logits, dim=1)[0]
            vals, idxs = torch.topk(probs, k=min(topk, probs.shape[0]))

        results: list[dict[str, Any]] = []
        for score, idx in zip(vals.tolist(), idxs.tolist()):
            label = self._labels[idx] if idx < len(self._labels) else f"class_{idx}"
            results.append({"label": label, "confidence": round(float(score), 6)})
        return results


STATE = RuntimeState(
    started_at_monotonic=monotonic(),
    started_at_utc=datetime.now(timezone.utc),
    version=os.getenv("AI_MODERATION_VERSION", "stable"),
)
MODERATOR = GpuImageModerator()


def _infer_error_response(
    *,
    now_utc: str,
    detail: str,
    status_code: int,
    failure_domain: str,
) -> JSONResponse:
    """Structured errors so demos can separate GPU/runtime issues from KOTA network drops."""
    notes: dict[str, str] = {
        "cuda_environment": (
            "CUDA could not start in this pod (drivers/devices/image). Compare with ACTIVE on kotactl: "
            "this is an environment/stack problem, not 'KOTA dropped SYN on :8000'."
        ),
        "gpu_runtime": (
            "The HTTP POST reached FastAPI before this failed—so TCX did not silently black-hole this request. "
            "Under ACTIVE,CUDA/PyTorch/driver errors indicate cluster GPU plumbing, not the NVML verdict line item."
        ),
        "validation": "Malformed or empty upload from the client.",
        "application": "Unexpected inference error after the request reached the application layer.",
    }
    return JSONResponse(
        status_code=status_code,
        content={
            "detail": detail,
            "failure_domain": failure_domain,
            "request_reached_application": True,
            "demo_audience_note": notes.get(failure_domain, notes["application"]),
            "utc_time": now_utc,
        },
    )


def _infer_failure_domain(exc: BaseException) -> str:
    """Map exception text to coarse domain for presenters."""
    blob = str(exc).lower()
    if "unavailable" in blob and "cuda" in blob:
        return "cuda_environment"
    if any(x in blob for x in ("cuda", "nvidia", "cudnn", "kernels might be asynchronously")):
        return "gpu_runtime"
    return "application"


def _infer_browser_timeout_ms() -> int:
    """Optional client-side cap for /process fetch (0 = browser default, no cap).

    Use a small value (e.g. 800) only when the model is warmed and you want the UI
    to report a quick 'network path' timeout during TCX demos — cold start can exceed 1s.
    """
    raw = os.getenv("INFER_BROWSER_TIMEOUT_MS", "").strip()
    if not raw:
        return 0
    ms = int(raw, 10)
    if not (0 <= ms <= 600_000):
        raise ValueError(f"INFER_BROWSER_TIMEOUT_MS out of range: {ms}")
    return ms


def _browser_admin_tcp_port() -> int:
    """Port the browser uses to reach /admin on the demo host.

    Inside the pod this is ADMIN_PORT (2000). With NodePort, set ADMIN_BROWSER_PORT
    to the published NodePort (e.g. 32000) so remote UIs hitting :30800 still resolve admin.
    """
    raw = os.getenv("ADMIN_BROWSER_PORT")
    if raw is None or raw.strip() == "":
        raw = os.getenv("ADMIN_PORT", "2000")
    p = int(raw, 10)
    if not (1 <= p <= 65535):
        raise ValueError(f"ADMIN_BROWSER_PORT/ADMIN_PORT out of range: {p}")
    return p


_DEMO_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KOTA Image Moderation Demo</title>
  <style>
    :root {
      --bg: #f3f5f8;
      --panel: #ffffff;
      --text: #1e2430;
      --muted: #5b6472;
      --line: #d9dee7;
      --ok: #0a8f46;
      --bad: #b42318;
      --btn: #2055d6;
      --btn-hover: #1a46b4;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    .container {
      max-width: 760px;
      margin: 0 auto;
      padding: 12px;
    }
    h1 { margin: 0 0 4px; font-size: 20px; }
    .subtitle { margin: 0 0 10px; color: var(--muted); font-size: 12px; }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 10px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px;
      box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05);
    }
    .panel h2 {
      margin: 0 0 8px;
      font-size: 15px;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      margin-bottom: 8px;
    }
    button {
      border: 0;
      border-radius: 7px;
      background: var(--btn);
      color: #fff;
      padding: 7px 10px;
      font-size: 12px;
      cursor: pointer;
    }
    input[type="file"] { font-size: 12px; }
    button:hover { background: var(--btn-hover); }
    .status {
      margin: 4px 0 8px;
      font-weight: 600;
      min-height: 16px;
      font-size: 12px;
    }
    .status.ok { color: var(--ok); }
    .status.bad { color: var(--bad); }
    .image-box {
      width: 100%;
      min-height: 160px;
      border: 1px dashed var(--line);
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #fbfcfe;
      overflow: hidden;
      margin-bottom: 8px;
    }
    .image-box img {
      max-width: 100%;
      max-height: 210px;
      object-fit: contain;
      display: none;
    }
    .image-placeholder {
      color: var(--muted);
      font-size: 12px;
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      background: #0f172a;
      color: #d9e3f0;
      border-radius: 8px;
      padding: 8px;
      max-height: 130px;
      overflow: auto;
      font-size: 11px;
    }
    ol {
      margin: 4px 0 0;
      padding-left: 18px;
      font-size: 12px;
      line-height: 1.35;
    }
    .predictions {
      max-height: 96px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 6px 8px;
      background: #fcfdff;
    }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      align-items: start;
    }
    .tiny {
      margin: 0 0 6px;
      color: var(--muted);
      font-size: 11px;
    }
    details {
      margin-top: 8px;
    }
    summary {
      cursor: pointer;
      font-size: 12px;
      color: var(--muted);
    }
    @media (max-width: 620px) {
      .row { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>KOTA AI Guard Demo</h1>
    <p class="subtitle">Inference path on port 8000, admin path on port 2000.</p>
    <div class="grid">
      <section class="panel">
        <h2>Inference Panel (/process)</h2>
        <p class="tiny">Compact view for four-quadrant demos.</p>
        <div class="actions">
          <input id="img" type="file" accept="image/*" />
          <button onclick="runInference()">Run Inference</button>
          <button onclick="refreshAdmin()">Refresh Admin</button>
        </div>
        <div class="status" id="inferStatus"></div>
        <div class="tiny" id="inferLastUtc">Last inference response UTC: -</div>
        <div class="row">
          <div>
            <div class="image-box">
              <span class="image-placeholder" id="imagePlaceholder">Upload an image to preview.</span>
              <img id="imagePreview" alt="Uploaded preview" />
            </div>
          </div>
          <div>
            <div><strong>Top Predictions</strong></div>
            <div class="predictions">
              <ol id="predictionsList"></ol>
            </div>
            <div style="margin-top:8px;"><strong>Admin Status</strong></div>
            <div class="status" id="adminStatus"></div>
          </div>
        </div>
        <details>
          <summary>Show JSON responses</summary>
          <div style="margin-top:6px;"><strong>Inference JSON</strong></div>
          <pre id="inferResult">{}</pre>
          <div style="margin-top:6px;"><strong>Admin JSON</strong></div>
          <pre id="adminResult">{}</pre>
        </details>
      </section>
    </div>
  </div>
  <script>
    const imgInput = document.getElementById("img");
    const imagePreview = document.getElementById("imagePreview");
    const imagePlaceholder = document.getElementById("imagePlaceholder");
    const inferResult = document.getElementById("inferResult");
    const inferStatus = document.getElementById("inferStatus");
    const predictionsList = document.getElementById("predictionsList");
    const inferLastUtc = document.getElementById("inferLastUtc");
    const adminResult = document.getElementById("adminResult");
    const adminStatus = document.getElementById("adminStatus");

    imgInput.addEventListener("change", function () {
      const file = imgInput.files[0];
      if (!file) {
        imagePreview.style.display = "none";
        imagePreview.src = "";
        imagePlaceholder.style.display = "block";
        return;
      }
      const url = URL.createObjectURL(file);
      imagePreview.src = url;
      imagePreview.style.display = "block";
      imagePlaceholder.style.display = "none";
    });

    function setStatus(el, text, ok) {
      el.textContent = text;
      el.className = ok ? "status ok" : "status bad";
    }

    function pretty(value) {
      return JSON.stringify(value, null, 2);
    }

    const INFER_FETCH_MS = __KOTA_INFER_FETCH_MS__;
    function inferTransportFailure(kind, e, extras) {
      var mn = e && e.name ? e.name : "";
      var timed = mn === "TimeoutError" || (mn === "AbortError" && INFER_FETCH_MS > 0);
      var netLike =
        timed ||
        mn === "AbortError" ||
        /Failed to fetch|NetworkError|Load failed/i.test(String(e));
      var human =
        timed
          ? "Network timeout — the browser stopped waiting for /process with no usable HTTP reply (matches a short CURL_MAXTIME_AI-style failure)."
          : netLike
            ? "Network / dataplane failure — no HTTP reply from /process (e.g. :8000 dropped or stalled on path; not FastAPI CUDA JSON)."
            : "Inference client error — see kota_demo_transport JSON.";
      setStatus(inferStatus, human, false);
      inferLastUtc.textContent = "Last inference attempt UTC: " + new Date().toISOString();
      inferResult.textContent = pretty(
        Object.assign(
          {
            kota_demo_transport: true,
            kind: timed ? "timeout" : netLike ? "network" : kind || "unknown",
            audience_note:
              timed
                ? "This object is synthesized in the demo UI: the TCP/HTTP exchange did not complete before the deadline (browser AbortSignal.timeout or stalled fetch)."
                : netLike
                  ? "This object is synthesized in the demo UI: no HTTP response was received — compare with CURL exit 28 on a capped curl -m."
                  : "Synthetic client-side error envelope for the demo.",
            error_name: mn || "(none)",
            message: String(e),
            client_cap_ms: INFER_FETCH_MS > 0 ? INFER_FETCH_MS : null,
          },
          extras || {},
        ),
      );
    }
    async function runInference() {
      const file = imgInput.files[0];
      if (!file) {
        setStatus(inferStatus, "Pick an image first.", false);
        return;
      }
      const form = new FormData();
      form.append("image", file);
      predictionsList.innerHTML = "";
      inferResult.textContent = pretty({
        kota_demo_transport: true,
        kind: "pending",
        audience_note: "Waiting for POST /process…",
      });
      try {
        const req = { method: "POST", body: form };
        if (INFER_FETCH_MS > 0 && typeof AbortSignal !== "undefined" && AbortSignal.timeout) {
          req.signal = AbortSignal.timeout(INFER_FETCH_MS);
        }
        const res = await fetch("/process", req);
        const text = await res.text();
        var body = null;
        var parseErr = null;
        if (text.trim() !== "") {
          try {
            body = JSON.parse(text);
          } catch (pe) {
            parseErr = pe;
          }
        }
        if (parseErr) {
          setStatus(inferStatus, "Non-JSON body — unlikely from FastAPI /process", false);
          inferLastUtc.textContent = "Last inference attempt UTC: " + new Date().toISOString();
          inferResult.textContent = pretty({
            kota_demo_transport: true,
            kind: "invalid_json_body",
            http_status: res.status,
            audience_note:
              "Response was received but JSON.parse failed; may be HTML from a proxy or an incomplete body.",
            body_snippet: text.slice(0, 1200),
          });
          return;
        }
        if (!res.ok) {
          setStatus(inferStatus, "HTTP error — request reached a server stack (often FastAPI); see JSON", false);
          inferLastUtc.textContent =
            "Last inference response UTC: " +
            (body && body.utc_time ? body.utc_time : new Date().toISOString());
          inferResult.textContent = pretty(body || { detail: "(empty body)", http_status: res.status });
          return;
        }
        /* res.ok */
        if (!body || typeof body !== "object" || Object.keys(body).length === 0) {
          setStatus(inferStatus, "HTTP 200 but empty/minimal JSON — invalid inference response shape", false);
          inferLastUtc.textContent = "Last inference attempt UTC: " + new Date().toISOString();
          inferResult.textContent = pretty({
            kota_demo_transport: true,
            kind: "empty_http_body",
            http_status: res.status,
            audience_note:
              'Do not trust a green banner if Inference JSON looked like "{}": success requires status==="ok" and top_predictions[].',
          });
          return;
        }
        if (body.status !== "ok" || !Array.isArray(body.top_predictions)) {
          setStatus(inferStatus, "HTTP 200 but not a successful inference envelope", false);
          inferResult.textContent = pretty(body);
          inferLastUtc.textContent =
            "Last inference response UTC: " + (body.utc_time || new Date().toISOString());
          return;
        }
        inferResult.textContent = pretty(body);
        const utc = body.utc_time || new Date().toISOString();
        inferLastUtc.textContent = "Last inference response UTC: " + utc;
        setStatus(inferStatus, "Inference successful", true);
        body.top_predictions.forEach(function (pred) {
          const li = document.createElement("li");
          const confidence = (Number(pred.confidence) * 100).toFixed(2);
          li.textContent = pred.label + " (" + confidence + "%)";
          predictionsList.appendChild(li);
        });
      } catch (e) {
        inferTransportFailure(null, e, null);
      }
    }

    async function refreshAdmin() {
      const adminUrl = window.location.protocol + "//" + window.location.hostname + ":" + __KOTA_BROWSER_ADMIN_PORT__ + "/admin";
      try {
        const res = await fetch(adminUrl);
        const body = await res.json();
        adminResult.textContent = pretty(body);
        setStatus(adminStatus, "Admin API reachable", res.ok);
      } catch (e) {
        var mn = e && e.name ? e.name : "";
        var netLike =
          mn === "TimeoutError" ||
          mn === "AbortError" ||
          /Failed to fetch|NetworkError|Load failed/i.test(String(e));
        setStatus(
          adminStatus,
          netLike
            ? "No HTTP reply to admin URL — wrong port/host or network block (should match ADMIN_BROWSER_PORT / nodePort)."
            : "Admin API error",
          false,
        );
        adminResult.textContent = String(e);
      }
    }

    refreshAdmin();
  </script>
</body>
</html>"""


def create_ai_app() -> FastAPI:
    app = FastAPI(title="KOTA Image Moderation AI API")

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        pa = _browser_admin_tcp_port()
        ims = _infer_browser_timeout_ms()
        return (
            _DEMO_HTML.replace("__KOTA_BROWSER_ADMIN_PORT__", str(pa)).replace(
                "__KOTA_INFER_FETCH_MS__", str(ims)
            )
        )

    @app.post("/process")
    async def process(image: UploadFile = File(...)) -> dict[str, Any]:
        now_utc = datetime.now(timezone.utc).isoformat()
        content = await image.read()
        if not content:
            return _infer_error_response(
                now_utc=now_utc,
                detail="empty upload",
                status_code=400,
                failure_domain="validation",
            )
        try:
            outputs = MODERATOR.classify(content)
        except RuntimeError as e:
            if "CUDA error" in str(e) or "OS call failed" in str(e):
                # Schedule exit AFTER response is fully sent
                async def _delayed_exit():
                    await asyncio.sleep(0.5)  # give ASGI time to flush response
                    os._exit(1)
                asyncio.create_task(_delayed_exit())
                
                return JSONResponse(
                    status_code=503,
                    content={
                        "failure_domain": "gpu_runtime",
                        "detail": str(e),
                        "request_reached_application": True,
                        "demo_audience_note": (
                            "KOTA LSM Veto corrupted CUDA context. Process recycling for fresh GPU handle."
                        ),
                    },
                )
            return _infer_error_response(
                now_utc=now_utc,
                detail=str(e),
                status_code=503,
                failure_domain=_infer_failure_domain(e),
            )
        except Exception as e:
            return _infer_error_response(
                now_utc=now_utc,
                detail=f"inference failed: {e}",
                status_code=500,
                failure_domain=_infer_failure_domain(e),
            )
        return {
            "status": "ok",
            "model": "resnet50",
            "device": "cuda",
            "top_predictions": outputs,
            "utc_time": now_utc,
        }

    return app


def create_admin_app() -> FastAPI:
    app = FastAPI(title="KOTA Image Moderation Admin API")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/admin")
    def admin() -> dict[str, Any]:
        return {
            "uptime_seconds": round(monotonic() - STATE.started_at_monotonic, 3),
            "version": STATE.version,
            "utc_time": datetime.now(timezone.utc).isoformat(),
            "started_at": STATE.started_at_utc.isoformat(),
        }

    return app
