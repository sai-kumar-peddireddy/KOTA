# KOTA — Kernel Oversight for Trusted AI

## High-Level Design (HLD) — Community Edition

> **Identity:** Sovereign Linux Sentinel (కోట).<br>
> **Core Mission:** A Hardware-to-Network Interlock that gates network traffic at the physical NIC based on real-time GPU hardware health and Seccomp-style behavioral profiles.

---

```mermaid
graph TB
    subgraph "Hardware & Metadata Layer (Source of Truth)"
        GPU["NVIDIA GPU /dev/nvidia0"]
        OCI_CFG["OCI config.json (/run/containerd/...)"]
        PROC_FS["/proc filesystem"]
    end

    subgraph "User Space: KOTA Sentinel (kotad)"
        direction TB
        NVML["NVML Telemetry: Polling/Events"]
        Resolver["PodResolver: Zero-Socket Discovery"]
        Decision["Decision Engine: State Machine"]
        YAML_Profiles["YAML Profiles: Port/Hardware Logic"]
    end

    subgraph "Kernel Space: eBPF Sovereign Enforcement"
        direction LR
        StatusMap{{"StatusMap: BPF_MAP_HASH <br/> Key: Cgroup Inode <br/> Val: Health/Violation Bit"}}
        
        SCALPEL["tcx/ingress: The Scalpel <br/> (Attached to lxc* interface)"]
        VETO["lsm/file_ioctl: Hardware Veto <br/> (Attached to GPU driver)"]
    end

    subgraph "Network & Application Plane"
        CILIUM["Cilium CNI: Optimized Fast-Path"]
        APP_POD["AI Application Container"]
    end

    %% Flow Relationships
    GPU -- "Telemetry (OOM/Thermal)" --> NVML
    OCI_CFG -- "Discovery (Labels/Profile)" --> Resolver
    PROC_FS -- "Inode/PID Mapping" --> Resolver
    
    NVML --> Decision
    Resolver --> Decision
    YAML_Profiles --> Decision
    
    Decision -- "Atomic Update" --> StatusMap

    %% Enforcement Relationships
    CILIUM -- "Teleported Packet" --> SCALPEL
    SCALPEL -- "Check Bit" --> StatusMap
    SCALPEL -- "Drop/Pass" --> APP_POD

    APP_POD -- "GPU System Call" --> VETO
    VETO -- "Check Bit" --> StatusMap
    VETO -- "Allow/EACCES" --> GPU
```

### Policy and verdicts

- **Profiles:** Port and hardware policy are defined in **YAML** files on the host; the Sentinel loads them by `profile_id` (from OCI labels at discovery time). OCI **`config.json`** remains the runtime metadata source for container identity and labels.
- **Verdicts:** Enforcement uses **ACTIVE** and **VIOLATION** only (see `docs/flow.md`). There is no separate quarantine tier in this edition.