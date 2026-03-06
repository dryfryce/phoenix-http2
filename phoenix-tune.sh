#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════╗
# ║         🔥🐦 PHOENIX KERNEL MAX FINE TUNER 🐦🔥          ║
# ║     Maximum performance tuning for HTTP/2 flood ops      ║
# ╚══════════════════════════════════════════════════════════╝
set -euo pipefail

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
BLD='\033[1m'
NC='\033[0m'

banner() {
  echo -e "${RED}"
  echo "  ██████╗ ██╗  ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗"
  echo "  ██╔══██╗██║  ██║██╔═══██╗██╔════╝████╗  ██║██║╚██╗██╔╝"
  echo "  ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║██║ ╚███╔╝ "
  echo "  ██╔═══╝ ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ "
  echo "  ██║     ██║  ██║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗"
  echo "  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
  echo -e "${NC}"
  echo -e "${YLW}  🔥 KERNEL MAX FINE TUNER — Attack VPS Edition 🔥${NC}"
  echo -e "${CYN}  Tuning for maximum HTTP/2 flood throughput${NC}"
  echo ""
}

log_ok()   { echo -e "  ${GRN}✅ $1${NC}"; }
log_warn() { echo -e "  ${YLW}⚠️  $1${NC}"; }
log_fire() { echo -e "  ${RED}🔥 $1${NC}"; }
log_info() { echo -e "  ${CYN}ℹ️  $1${NC}"; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run as root!${NC}"; exit 1
  fi
}

# ─── BBR ──────────────────────────────────────────────────
enable_bbr() {
  echo -e "\n${BLD}[1/6] Congestion Control → BBR + FQ${NC}"
  modprobe tcp_bbr 2>/dev/null || true
  if lsmod | grep -q tcp_bbr; then
    sysctl -w net.core.default_qdisc=fq >/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null
    log_ok "BBR enabled, qdisc=fq"
  else
    log_warn "BBR module not available — falling back to cubic+fq"
    sysctl -w net.core.default_qdisc=fq >/dev/null
  fi
}

# ─── NETWORK CORE ─────────────────────────────────────────
tune_network() {
  echo -e "\n${BLD}[2/6] Network Core Buffers & Limits${NC}"

  # Backlog + connections
  sysctl -w net.core.somaxconn=65535 >/dev/null
  sysctl -w net.core.netdev_max_backlog=250000 >/dev/null
  sysctl -w net.ipv4.tcp_max_syn_backlog=65535 >/dev/null
  sysctl -w net.ipv4.tcp_max_tw_buckets=2000000 >/dev/null
  log_ok "Backlog: somaxconn=65535, netdev=250000, syn_backlog=65535, tw_buckets=2M"

  # Buffers — sized for 58GB RAM (use ~30% for net)
  local rmem=536870912  # 512MB
  local wmem=536870912
  sysctl -w net.core.rmem_max=$rmem >/dev/null
  sysctl -w net.core.wmem_max=$wmem >/dev/null
  sysctl -w net.core.rmem_default=262144 >/dev/null
  sysctl -w net.core.wmem_default=262144 >/dev/null
  sysctl -w net.ipv4.tcp_rmem="4096 262144 $rmem" >/dev/null
  sysctl -w net.ipv4.tcp_wmem="4096 262144 $wmem" >/dev/null
  sysctl -w net.ipv4.udp_rmem_min=8192 >/dev/null
  sysctl -w net.ipv4.udp_wmem_min=8192 >/dev/null
  log_ok "Buffers: rmem/wmem_max=512MB"

  # Socket memory (bytes: min / pressure / max) — scaled for 58GB
  sysctl -w net.ipv4.tcp_mem="786432 1048576 26214400" >/dev/null
  log_ok "tcp_mem tuned (up to ~100GB socket memory)"

  # Ports
  sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null
  log_ok "Local port range: 1024-65535"

  # Netdev budget for packet processing
  sysctl -w net.core.netdev_budget=1000 >/dev/null
  sysctl -w net.core.netdev_budget_usecs=8000 >/dev/null
  log_ok "netdev_budget=1000, budget_usecs=8000"
}

# ─── TCP BEHAVIOR ─────────────────────────────────────────
tune_tcp() {
  echo -e "\n${BLD}[3/6] TCP Behavior & Timers${NC}"

  sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null
  sysctl -w net.ipv4.tcp_fin_timeout=10 >/dev/null
  sysctl -w net.ipv4.tcp_keepalive_time=60 >/dev/null
  sysctl -w net.ipv4.tcp_keepalive_intvl=10 >/dev/null
  sysctl -w net.ipv4.tcp_keepalive_probes=6 >/dev/null
  log_ok "tw_reuse=1, fin_timeout=10s, keepalive=60/10/6"

  sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null
  sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null
  sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null
  sysctl -w net.ipv4.tcp_sack=1 >/dev/null
  sysctl -w net.ipv4.tcp_dsack=1 >/dev/null
  sysctl -w net.ipv4.tcp_fack=0 >/dev/null  # deprecated in newer kernels
  log_ok "fastopen=3 (client+server), MTU probing=1, SACK/DSACK=1"

  sysctl -w net.ipv4.tcp_syn_retries=2 >/dev/null
  sysctl -w net.ipv4.tcp_synack_retries=2 >/dev/null
  sysctl -w net.ipv4.tcp_retries2=5 >/dev/null
  log_ok "syn_retries=2, synack_retries=2, retries2=5 (fast failure)"

  sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null
  sysctl -w net.ipv4.tcp_no_metrics_save=1 >/dev/null
  sysctl -w net.ipv4.tcp_moderate_rcvbuf=1 >/dev/null
  log_ok "No slow-start after idle, no metrics save"

  # Low-latency mode
  sysctl -w net.ipv4.tcp_low_latency=1 2>/dev/null || true
  log_ok "TCP low-latency mode requested"

  # Increase orphan limits for rapid RST flood
  sysctl -w net.ipv4.tcp_max_orphans=1000000 >/dev/null
  sysctl -w net.ipv4.tcp_orphan_retries=1 >/dev/null
  log_ok "tcp_max_orphans=1M, orphan_retries=1"
}

# ─── FILE DESCRIPTORS & MEMORY ────────────────────────────
tune_limits() {
  echo -e "\n${BLD}[4/6] File Descriptors & Memory${NC}"

  # System-wide fd limit
  sysctl -w fs.file-max=10000000 >/dev/null
  sysctl -w fs.nr_open=10000000 >/dev/null
  log_ok "fs.file-max=10M, fs.nr_open=10M"

  # VM tuning — don't swap, keep memory for network
  sysctl -w vm.swappiness=0 >/dev/null
  sysctl -w vm.dirty_ratio=40 >/dev/null
  sysctl -w vm.dirty_background_ratio=10 >/dev/null
  sysctl -w vm.overcommit_memory=1 >/dev/null
  sysctl -w vm.overcommit_ratio=90 >/dev/null
  log_ok "vm: swappiness=0, overcommit=1, dirty tuned"

  # Huge pages for memory efficiency (optional, won't error if unavailable)
  echo always > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
  log_ok "Transparent hugepages=always"

  # Persist limits in /etc/security/limits.conf
  cat > /etc/security/limits.d/phoenix.conf << 'LIMITS'
# Phoenix — max performance limits
*         soft    nofile    1000000
*         hard    nofile    1000000
root      soft    nofile    1000000
root      hard    nofile    1000000
*         soft    nproc     unlimited
*         hard    nproc     unlimited
*         soft    memlock   unlimited
*         hard    memlock   unlimited
LIMITS
  log_ok "limits.d/phoenix.conf written (1M fds, unlimited procs/memlock)"

  # Apply to current session
  ulimit -n 1000000 2>/dev/null || log_warn "ulimit -n: needs re-login to take full effect"
  ulimit -u unlimited 2>/dev/null || true
}

# ─── PERSIST sysctl ───────────────────────────────────────
persist_sysctl() {
  echo -e "\n${BLD}[5/6] Persisting to /etc/sysctl.d/99-phoenix.conf${NC}"

  cat > /etc/sysctl.d/99-phoenix.conf << 'SYSCTL'
# 🔥 Phoenix Kernel Max Fine Tuner — auto-generated
# Applied at boot via sysctl.d

# BBR + FQ
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000

# Buffers
net.core.rmem_max = 536870912
net.core.wmem_max = 536870912
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 262144 536870912
net.ipv4.tcp_wmem = 4096 262144 536870912
net.ipv4.tcp_mem = 786432 1048576 26214400

# Ports
net.ipv4.ip_local_port_range = 1024 65535

# TCP behaviour
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_retries2 = 5
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_max_orphans = 1000000
net.ipv4.tcp_orphan_retries = 1

# Netdev
net.core.netdev_budget = 1000
net.core.netdev_budget_usecs = 8000

# FDs
fs.file-max = 10000000
fs.nr_open = 10000000

# VM
vm.swappiness = 0
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.overcommit_memory = 1
vm.overcommit_ratio = 90
SYSCTL

  sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-phoenix.conf >/dev/null
  log_ok "sysctl persisted and reloaded"
}

# ─── SUMMARY ──────────────────────────────────────────────
print_summary() {
  echo -e "\n${BLD}[6/6] Verification${NC}"
  echo ""
  printf "  %-35s %s\n" "Setting" "Value"
  printf "  %-35s %s\n" "-------" "-----"
  for key in \
    net.core.somaxconn \
    net.core.netdev_max_backlog \
    net.ipv4.tcp_max_syn_backlog \
    net.ipv4.tcp_congestion_control \
    net.core.default_qdisc \
    net.core.rmem_max \
    net.core.wmem_max \
    net.ipv4.tcp_fin_timeout \
    net.ipv4.tcp_tw_reuse \
    net.ipv4.tcp_fastopen \
    net.ipv4.tcp_max_orphans \
    fs.file-max \
    vm.swappiness; do
    val=$(sysctl -n $key 2>/dev/null || echo "n/a")
    printf "  ${CYN}%-35s${NC} ${GRN}%s${NC}\n" "$key" "$val"
  done

  echo ""
  echo -e "  ${GRN}Current ulimit -n:${NC} $(ulimit -n)"
  echo ""
  echo -e "${YLW}  ⚡ Phoenix kernel tuning COMPLETE. Re-login for ulimit to apply fully.${NC}"
  echo -e "${RED}  🔥 Machine is now primed for maximum HTTP/2 throughput. 🐦${NC}"
  echo ""
}

# ─── MAIN ─────────────────────────────────────────────────
main() {
  banner
  check_root
  enable_bbr
  tune_network
  tune_tcp
  tune_limits
  persist_sysctl
  print_summary
}

main "$@"
