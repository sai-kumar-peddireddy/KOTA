#!/usr/bin/env bash
# KOTA CE — preflight for operator / lab nodes (Cilium + lxc* + NVIDIA context).
# Exits 0 when required BPF runtime is present; prints actionable messages to stderr on failure.

usage() {
  cat >&2 <<'EOF'
Usage: check_kota_env.sh [--json]

  --json   Print a minimal JSON object with check results (still uses exit codes).

Environment checks:
  - bpffs mounted at /sys/fs/bpf (writable)
  - bpftool in PATH
  - Kernel configuration (when readable): CONFIG_BPF, CONFIG_BPF_SYSCALL,
    CONFIG_DEBUG_INFO_BTF (CO-RE), CONFIG_BPF_LSM (optional warning if off)

Later operator commands (documented for ACCEPT-style verification):
  bpftool map list | grep -i kota
  bpftool prog list
EOF
}

json_mode=0
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ "${1:-}" == "--json" ]]; then
  json_mode=1
fi

errors=0
warnings=0

warn() {
  warnings=$((warnings + 1))
  echo "check_kota_env: warning: $*" >&2
}

fail() {
  errors=$((errors + 1))
  echo "check_kota_env: error: $*" >&2
}

pass() {
  if [[ "$json_mode" -eq 0 ]]; then
    echo "check_kota_env: ok: $*"
  fi
}

kver=$(uname -r)

if ! command -v mountpoint >/dev/null 2>&1; then
  warn "mountpoint(1) not found; skipping strict bpffs mountpoint check"
  if [[ ! -d /sys/fs/bpf ]]; then
    fail "/sys/fs/bpf missing. Mount bpffs: sudo mount -t bpf bpffs /sys/fs/bpf"
  elif [[ ! -w /sys/fs/bpf && ${EUID:-$(id -u)} -eq 0 ]]; then
    fail "/sys/fs/bpf is not writable even as root (check mount options / permissions)"
  elif [[ ! -w /sys/fs/bpf ]]; then
    warn "/sys/fs/bpf not writable as this user; run kotad / pinning under sudo (expected on lab nodes)"
    pass "bpffs path /sys/fs/bpf exists"
  else
    pass "bpffs path /sys/fs/bpf exists and is writable"
  fi
else
  if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    fail "bpffs not mounted at /sys/fs/bpf. Run: sudo mount -t bpf bpffs /sys/fs/bpf"
  elif [[ ! -w /sys/fs/bpf && ${EUID:-$(id -u)} -eq 0 ]]; then
    fail "/sys/fs/bpf is not writable even as root (needed for map/program pins under /sys/fs/bpf/kota/)"
  elif [[ ! -w /sys/fs/bpf ]]; then
    warn "/sys/fs/bpf not writable as this user; pinning requires elevated privileges"
    pass "bpffs mounted at /sys/fs/bpf"
  else
    pass "bpffs mounted and writable at /sys/fs/bpf"
  fi
fi

if ! command -v bpftool >/dev/null 2>&1; then
  fail "bpftool not in PATH (install the bpftool package, often from kernel source or distro iproute2 extras)"
else
  pass "bpftool: $(command -v bpftool)"
fi

config_val() {
  local key="$1"
  local path="$2"
  if [[ "$path" == *.gz ]]; then
    zgrep -E "^${key}=" "$path" 2>/dev/null | head -n1
  else
    grep -E "^${key}=" "$path" 2>/dev/null | head -n1
  fi
}

check_kernel_config() {
  local cfg_path=""
  for candidate in "/boot/config-${kver}" "/lib/modules/${kver}/build/.config"; do
    if [[ -r "$candidate" ]]; then
      cfg_path="$candidate"
      break
    fi
  done
  if [[ -z "$cfg_path" && -r /proc/config.gz ]]; then
    cfg_path="/proc/config.gz"
  fi

  if [[ -z "$cfg_path" ]]; then
    warn "no readable kernel config (tried /boot/config-${kver}, module build .config, /proc/config.gz); skipping CONFIG_* checks"
    return
  fi

  pass "kernel config: ${cfg_path}"

  local need=(CONFIG_BPF CONFIG_BPF_SYSCALL CONFIG_DEBUG_INFO_BTF)
  for key in "${need[@]}"; do
    local line
    line=$(config_val "$key" "$cfg_path")
    if [[ -z "$line" ]]; then
      fail "${key} not found in ${cfg_path} (kernel may be too old or config stripped)"
      continue
    fi
    if [[ "$line" == *"=y"* || "$line" == *"=m"* ]]; then
      pass "${line}"
    else
      fail "${key} is disabled in kernel config (${line})"
    fi
  done

  local lsm
  lsm=$(config_val CONFIG_BPF_LSM "$cfg_path")
  if [[ -z "$lsm" || "$lsm" == *"=n"* ]]; then
    warn "CONFIG_BPF_LSM not enabled; LSM Veto attach will not be available on this kernel"
  else
    pass "${lsm}"
  fi
}

check_kernel_config

if ! command -v nvidia-smi >/dev/null 2>&1; then
  warn "nvidia-smi not found; GPU health / ioctl paths (see docs/HLD.md) cannot be exercised on this host"
else
  pass "NVIDIA userspace: nvidia-smi present"
fi

if [[ "$json_mode" -eq 1 ]]; then
  printf '{"kver":"%s","errors":%d,"warnings":%d}\n' "$kver" "$errors" "$warnings"
fi

if [[ "$errors" -gt 0 ]]; then
  echo "check_kota_env: ${errors} error(s), ${warnings} warning(s). Fix errors above before loading KOTA BPF objects." >&2
  exit 1
fi

if [[ "$json_mode" -eq 0 ]]; then
  echo "check_kota_env: all required checks passed (${warnings} warning(s))."
fi
exit 0
