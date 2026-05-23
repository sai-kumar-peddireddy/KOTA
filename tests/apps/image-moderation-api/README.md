# KOTA Image Moderation Demo App

This is a real GPU-backed demo service for KOTA use-case storytelling:

- AI inference path on port `8000` (`POST /process`)
- Management path on port `2000` (`GET /admin`)
- Simple HTML UI on `GET /` (served from AI service)

The inference path uses `torchvision` `ResNet50` and moves model + tensors to CUDA.

## Kubernetes vs Docker (important for demos)

**Full KOTA demo (enrollment + enforcement narrative): deploy this image as Pods on your cluster.**

Sentinel aligns policy to **kubelet/cgroup/pod identity**, labels, and CNI correlation. Running the container only with **`docker run` on the node** skips that path: you can smoke-test CUDA and `/process`, but Sentinel will not observe the workload the same way—**do not** use Docker-only runs to validate auto-enrollment, ARMED state, or the End-to-End story.

Kubernetes manifests live under **`k8s/`** in this directory. Lab build order: **`docs/tasks/sprints-v5.0-demo-narrative.md`** + **`docs/tasks/demo.md`**.

### How you actually run it on Kubernetes

You do **not** run Python on the host manually. You **`docker build`** the image, get that image **onto the cluster** (push to a registry *or* load into kind/minikube—**public registry is optional**), then **`kubectl apply`** the YAML in **`k8s/`** and use **`kubectl port-forward`** or a Service/Ingress to reach ports **8000** and **2000**.

Step-by-step:** [`k8s/README.md`](./k8s/README.md).

## Build

```bash
docker build -t kota-image-moderation tests/apps/image-moderation-api
```

## Run locally (smoke-test only)

```bash
docker run --rm --gpus all -p 8000:8000 -p 2000:2000 kota-image-moderation
```

## Quick checks

```bash
curl -s http://localhost:2000/admin | jq
curl -s -F image=@/path/to/image.jpg http://localhost:8000/process | jq
```
