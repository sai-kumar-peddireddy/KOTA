```mermaid
graph TD
    subgraph "Sovereign Discovery Layer (PodResolver.cpp)"
        CR_MON["Cgroup Monitor (tp/cgroup/cgroup_mkdir)"]
        FCP["find_cgroup_path(): Inode -> Path Mapping"]
        PCID["parse_container_id(): Extracts 64-char Hex CID"]
        PUID["parse_pod_uid(): Normalizes Pod UUID"]
        RP_IP["read_pod_ip(): setns() + eth0 netns lookup"]
        VETH_RESOLVE["host_veth_ifname_for_pid(): iflink cross-ref"]
        META["read_runtime_meta(): OCI config.json Parsing"]
    end

    subgraph "User-Space Control Plane (Sentinel/kotad)"
        POL_ENG["Decision Engine: YAML Profile Logic"]
        NVML_POLL["NVML Poller: GPU OOM/Temp/ECC Status"]
        MAP_TX["Map Updater: Atomic BPF_ANY Writes"]
    end

    subgraph "Kernel-Space Memory (Interlock State)"
        StatusMap{{"StatusMap (BPF_MAP_TYPE_HASH) <br/> Key: Cgroup Inode <br/> Val: [Verdict | Profile_ID | Cilium_ID]"}}
        IP_Ino_Map{{"IP_to_Inode (BPF_MAP_TYPE_HASH) <br/> Key: Pod IPv4 <br/> Val: Cgroup Inode"}}
    end

    subgraph "Sovereign Enforcement (eBPF Muscle)"
        TCX_SCALPEL["SEC('tcx/ingress') <br/> Target: lxc* (Host Veth) <br/> Logic: if(Blocked) & Port(AI) -> SHOT"]
        LSM_VETO["SEC('lsm/file_ioctl') <br/> Target: /dev/nvidia* <br/> Logic: if(Violation) -> -EACCES"]
    end

    %% Discovery Flow
    CR_MON -- "New Inode" --> FCP
    FCP --> PCID
    FCP --> PUID
    PCID --> META
    META -- "Labels (kota.ai/profile)" --> POL_ENG
    RP_IP -- "Resolved IP" --> MAP_TX
    VETH_RESOLVE -- "Attach Target" --> TCX_SCALPEL

    %% Health Flow
    NVML_POLL -- "Hardware Fault Event" --> POL_ENG
    POL_ENG -- "Enforce (Violation=1)" --> MAP_TX
    MAP_TX -- "Update" --> StatusMap
    MAP_TX -- "Attribution" --> IP_Ino_Map

    %% Enforcement Flow
    StatusMap -.-> TCX_SCALPEL
    StatusMap -.-> LSM_VETO
    TCX_SCALPEL -- "Pass/Drop" --> POD_NET["Pod Network Namespace"]
    LSM_VETO -- "Allow/Deny" --> GPU_DRV["NVIDIA Driver Context"]
```

🏛️ Component Responsibilities
1. KOTAD Sentinel (User Space)
Health Coordination: Monitors real-time GPU metrics (OOM events, ECC errors, thermal throttling) via NVML.

State Management: Manages **ACTIVE** vs **VIOLATION** verdicts per pod (see `docs/flow.md`). There is no separate quarantine tier: a hardware breach moves the pod straight to enforced **VIOLATION**; recovery applies hysteresis before returning to **ACTIVE**.

Atomic Map Updates: Performs atomic BPF map updates to ensure enforcement is updated without dropping existing healthy connections.

2. PodResolver (Discovery Engine)
Zero-Socket Resolution: Discovers container metadata by parsing the OCI **config.json** and **/proc** filesystem. **Policy** (ports, thresholds, AI vs management classes) comes from **YAML** profile files selected by the `kota.ai/profile` label (or equivalent), not from JSON policy documents.

Namespace Traversal: Enters the pod's network namespace using setns() to verify the internal eth0 IP address.

Veth Correlation: Matches the pod's internal iflink to the host-side lxc* interface name, providing the target for the Scalpel.

3. StatusMap (The Interlock)
Decentralized Truth: Acts as the shared memory between the Sentinel (User Space) and the BPF programs (Kernel Space).

Immutable Keys: Uses the Cgroup Inode as the primary key to ensure security is tied to the physical container life cycle, even if the IP address changes.

Enforcement Context: Stores the Verdict (Allow/Block) and the Profile_ID, which dictates which specific ports are restricted during a fault.

4. TCX Scalpel (Network Gate)
Surgical Enforcement: Attached to the lxc* interface, catching packets after they have been translated/teleported by the CNI.

Port-Aware Logic: Inspects incoming TCP/UDP ports. It selectively drops "AI/Data" traffic while allowing "Management/Probe" traffic based on the Pod's profile.

5. LSM Veto (Hardware Gate)
The Final Backstop: Attached to the file_ioctl hook on the GPU device driver (/dev/nvidia*).

Dynamic Command Blocking: Intercepts GPU execution commands. If the Pod is in a violation state, the kernel returns -EACCES, preventing the application from running AI logic on the silicon.