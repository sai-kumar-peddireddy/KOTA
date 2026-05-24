```mermaid
sequenceDiagram
    participant HW as GPU / Runtime (Filesystem)
    participant PR as PodResolver (Discovery)
    participant ST as Sentinel (kotad)
    participant Map as StatusMap (BPF Map)
    participant Scalpel as TCX Scalpel (Network Gate)
    participant Veto as LSM Veto (Hardware Gate)

    Note over HW, PR: PHASE 1: DISCOVERY (Zero-Socket) — OCI config.json + /proc; profile id binds to on-disk YAML policy
    HW->>PR: Cgroup Created (tp/cgroup/cgroup_mkdir)
    PR->>HW: Parse OCI config.json & /proc
    PR->>PR: Resolve Inode, Profile (Labels), & lxc* Interface
    PR->>ST: Pod Identity & Metadata
    ST->>Map: Initialize Entry (Verdict=ACTIVE, Profile_ID)

    Note over HW, ST: PHASE 2: MONITORING
    loop Every X Milliseconds / Event-Driven
        HW->>ST: NVML Telemetry (OOM, ECC, Thermal)
        ST->>ST: Compare against Thresholds/Policy
    end

    Note over ST, Veto: PHASE 3: ENFORCEMENT (The Veto)
    rect rgb(201, 204, 101)
        ST->>ST: Hardware Fault Detected!
        ST->>Map: Atomic Update (Verdict=VIOLATION)
        
        par Network Enforcement
            Scalpel->>Map: Lookup Inode/IP State
            Map-->>Scalpel: VIOLATION Found
            Scalpel->>Scalpel: Drop Packet on AI Ports (e.g., 8080)
        and Hardware Enforcement
            Veto->>Map: Lookup Inode State
            Map-->>Veto: VIOLATION Found
            Veto->>HW: Return -EACCES to GPU ioctl()
        end
    end

    Note over ST, HW: PHASE 4: RECOVERY
    ST->>ST: Hardware Recovery Benchmarks Met
    ST->>Map: Atomic Update (Verdict=ACTIVE)
    par Gates Open
        Scalpel->>Scalpel: Allow All Ports
    and Hardware Unlocked
        Veto->>HW: Allow GPU ioctl()
    end
```