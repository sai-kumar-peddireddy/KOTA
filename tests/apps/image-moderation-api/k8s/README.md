# Image moderation demo on Kubernetes

The app is **not** “run `python app.py` on the cluster” by hand. You **build a container image** (the `Dockerfile` runs `launcher.py`, which starts both Uvicorn servers on **8000** and **2000**), then you **schedule that image as a Pod** with `kubectl`. This directory holds a minimal manifest.

**Do you have to push to a public registry?** **No.** You only need *some* way for every **node that can run the Pod** to obtain the image:

- push to **any** registry you control (private GHCR, Harbor, ECR, etc.), **or**
- **load** the image into the cluster’s container runtime (common for **kind**, **minikube**, **Docker Desktop Kubernetes**, single-node labs).

---

## 1. Build the image (on a machine with Docker)

From the repo root:

```bash
docker build -t kota-image-moderation:latest tests/apps/image-moderation-api
```

---

## 2. Get the image onto the cluster (pick one path)

### A. Registry (works for any cluster; best default)

1. Tag for your registry, for example:
   - `docker tag kota-image-moderation:latest ghcr.io/<your-org>/kota-image-moderation:latest`
   - or `myregistry.local:5000/kota-image-moderation:latest`
2. `docker push …`
3. Edit `image-moderation-demo.yaml`: set `spec.template.spec.containers[0].image` to that full name.
4. If the registry is **private**, create an `imagePullSecret` and reference it in the Pod spec (see Kubernetes docs for `imagePullSecrets`).

You do **not** need a *public* registry unless you have no private option; many teams use **GHCR** or **Harbor** with auth.

### B. Kind (local clusters)

Load the built image into Kind so kubelet finds it **without** a registry:

```bash
kind load docker-image kota-image-moderation:latest --name <your-kind-cluster-name>
```

Keep Deployment `image: kota-image-moderation:latest` and use `imagePullPolicy: Never` **or** `IfNotPresent` depending on Kind version (often `Never` avoids pull attempts).

### C. Minikube

Build/load so Minikube’s Docker/CRI sees the tag:

```bash
eval "$(minikube docker-env)"
docker build -t kota-image-moderation:latest /path/to/repo/tests/apps/image-moderation-api
# then kubectl apply ...
```

Alternatively: `minikube image load kota-image-moderation:latest`.

### D. k3s (lab default: image never pushed)

Build on a host that reaches the cluster (often the GPU node itself), then **import straight into containerd**:

```bash
docker build -t kota-image-moderation:latest tests/apps/image-moderation-api
docker save kota-image-moderation:latest | sudo k3s ctr images import -
```

Keep `image: kota-image-moderation:latest` in YAML and **`imagePullPolicy: Never`** (or **`IfNotPresent`**) so the kubelet pulls from node-local storage only—**no Docker Hub**, no publishing step. Prefer **NodePort** or **`kubectl`-from-bastion** if SSH is how you drive the demo (see **`docs/tasks/demo.md`** day-of checklist).

### E. Same physical node as Kubelets (other bare-metal layouts)

Often you publish to an on-node registry (`localhost:5000`, internal Harbor) or automate `ctr`/nerdctl import—**kubectl does not automatically see images only in your laptop Docker**. Build/import **on** the worker you schedule to when in doubt.

---

## 3. GPU scheduling

Your cluster needs a GPU **device plugin** and correct resource limits in the manifest (`nvidia.com/gpu` naming varies). Edit **`image-moderation-demo.yaml`** until `kubectl describe pod` shows GPU binding and CUDA works inside:

```bash
kubectl exec -it deploy/kota-image-moderation -n kota-demo -- nvidia-smi
```

Adjust **namespace**, **labels** (`kota.ai/profile`), and **images** before you rely on this in production.

---

## 4. Apply and reach ports from your laptop

```bash
kubectl apply -f tests/apps/image-moderation-api/k8s/image-moderation-demo.yaml
kubectl wait --for=condition=Ready pod -l app=kota-image-moderation -n kota-demo --timeout=180s
kubectl port-forward svc/kota-image-moderation 8000:8000 2000:2000 -n kota-demo
```

In another terminal:

```bash
curl -s http://127.0.0.1:2000/admin
curl -s -F image=@/path/to/picture.jpg http://127.0.0.1:8000/process
```

---

## 5. Why not only `docker run` on the GPU node?

The same container **can** run with `docker run` for smoke tests, but the **filmed KOTA demo** expects **Kubernetes Pod identity**. See **`../README.md`** and **`docs/tasks/demo.md`**.

## Labels

Align **`kota.ai/profile`** in the manifest with your **`kotactl`** / policy story before filming.
