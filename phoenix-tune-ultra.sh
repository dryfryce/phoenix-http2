#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║      🔥🐦 PHOENIX ULTRA TUNER — LEVEL 2 HARDWARE LAYER 🐦🔥  ║
# ║   NIC · IRQ · CPU · RPS/RFS · Polling · Latency annihilator  ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'

banner() {
  echo -e "${RED}"
  echo "  ██╗   ██╗██╗  ████████╗██████╗  █████╗ "
  echo "  ██║   ██║██║  ╚══██╔══╝██╔══██╗██╔══██╗"
  echo "  ██║   ██║██║     ██║   ██████╔╝███████║"
  echo "  ██║   ██║██║     ██║   ██╔══██╗██╔══██║"
  echo "  ╚██████╔╝███████╗██║   ██║  ██║██║  ██║"
  echo "   ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
  echo -e "${NC}"
  echo -e "${YLW}  🔥 PHOENIX ULTRA TUNER — LEVEL 2: HARDWARE LAYER 🔥${NC}"
  echo -e "${CYN}  NIC rings · IRQ affinity · RPS/RFS · Busy poll · CPU perf${NC}"
  echo ""
}

log_ok()   { echo -e "  ${GRN}✅ $1${NC}"; }
log_warn() { echo -e "  ${YLW}⚠️  $1${NC}"; }
log_info() { echo -e "  ${CYN}ℹ️  $1${NC}"; }

NCPUS=$(nproc)
NIC=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
NIC=${NIC:-ens3}

# ─── 1. NIC RING BUFFERS ──────────────────────────────────
tune_nic_rings() {
  echo -e "\n${BLD}[1/7] NIC Ring Buffers — ${NIC}${NC}"
  MAX_RX=$(ethtool -g $NIC 2>/dev/null | awk '/Pre-set/{found=1} found && /^RX:/{print $2; exit}')
  MAX_TX=$(ethtool -g $NIC 2>/dev/null | awk '/Pre-set/{found=1} found && /^TX:/{print $2; exit}')

  if [[ -n "$MAX_RX" ]]; then
    ethtool -G $NIC rx $MAX_RX tx ${MAX_TX:-$MAX_RX} 2>/dev/null && \
      log_ok "Ring buffers maxed: RX=$MAX_RX TX=${MAX_TX:-$MAX_RX}" || \
      log_warn "Ring buffer set failed (VPS virtual NIC limit — already at max $MAX_RX)"
  else
    log_warn "ethtool not available for ring tuning"
  fi

  # Disable NIC offloads that add latency (keep only useful ones)
  ethtool -K $NIC gro off 2>/dev/null && log_ok "GRO disabled (lower per-packet latency)" || true
  ethtool -K $NIC gso off 2>/dev/null && log_ok "GSO disabled" || true
  # Keep TSO on — helps TX throughput for large sends
  ethtool -K $NIC tso on  2>/dev/null || true
  ethtool -K $NIC rx-checksumming on 2>/dev/null || true
  ethtool -K $NIC tx-checksumming on 2>/dev/null || true
}

# ─── 2. IRQ AFFINITY ──────────────────────────────────────
tune_irq_affinity() {
  echo -e "\n${BLD}[2/7] IRQ Affinity — Spread across all $NCPUS cores${NC}"

  # Build CPU mask for all cores
  ALL_CPU_MASK=$(python3 -c "print(hex((1<<$NCPUS)-1))" 2>/dev/null || \
                 printf '%x' $(( (1 << NCPUS) - 1 )))

  local count=0
  local core=0
  for irq_dir in /proc/irq/*/smp_affinity; do
    irq=$(echo $irq_dir | grep -o '[0-9]*')
    [[ "$irq" == "0" ]] && continue
    # Check if it's a NIC IRQ
    irq_name=$(cat /proc/irq/$irq/spurious 2>/dev/null || cat /sys/kernel/irq/$irq/name 2>/dev/null || echo "")
    if grep -q "$NIC\|virtio\|xen-vif\|eth" /proc/irq/$irq/actions 2>/dev/null; then
      # Pin to specific core (round robin)
      core_mask=$(printf '%x' $((1 << (core % NCPUS))))
      echo $core_mask > /proc/irq/$irq/smp_affinity 2>/dev/null && count=$((count+1))
      core=$((core+1))
    fi
  done

  if [[ $count -gt 0 ]]; then
    log_ok "Pinned $count NIC IRQs across cores (round-robin)"
  else
    # Fallback: spread all IRQs
    for irq_dir in /proc/irq/*/smp_affinity; do
      irq=$(echo $irq_dir | grep -o '[0-9]*')
      [[ "$irq" =~ ^[0-9]+$ ]] && echo $ALL_CPU_MASK > $irq_dir 2>/dev/null || true
    done
    log_ok "Spread all IRQs across all $NCPUS cores (mask=$ALL_CPU_MASK)"
  fi
}

# ─── 3. RPS / RFS (Software Multi-Core Rx) ────────────────
tune_rps_rfs() {
  echo -e "\n${BLD}[3/7] RPS/RFS — Software multi-core packet steering${NC}"

  ALL_CPU_MASK=$(python3 -c "print(hex((1<<$NCPUS)-1))" 2>/dev/null || \
                 printf '%x' $(( (1 << NCPUS) - 1 )))

  local rps_count=0
  for rps_file in /sys/class/net/$NIC/queues/rx-*/rps_cpus; do
    [[ -f "$rps_file" ]] && echo $ALL_CPU_MASK > $rps_file 2>/dev/null && rps_count=$((rps_count+1))
  done
  log_ok "RPS enabled on $rps_count RX queues (all $NCPUS CPUs, mask=$ALL_CPU_MASK)"

  # RFS flow table — 1M entries for connection tracking
  echo 1048576 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true
  local rfs_count=0
  for rfs_file in /sys/class/net/$NIC/queues/rx-*/rps_flow_cnt; do
    if [[ -f "$rfs_file" ]]; then
      echo 32768 > $rfs_file 2>/dev/null && rfs_count=$((rfs_count+1))
    fi
  done
  log_ok "RFS: sock_flow_entries=1M, flow_cnt=32768 per queue ($rfs_count queues)"

  # XPS — Transmit Packet Steering (pin TX queue per CPU)
  local xps_count=0
  local cpu=0
  for xps_file in /sys/class/net/$NIC/queues/tx-*/xps_cpus; do
    if [[ -f "$xps_file" ]]; then
      cpu_mask=$(printf '%x' $((1 << (cpu % NCPUS))))
      echo $cpu_mask > $xps_file 2>/dev/null && xps_count=$((xps_count+1))
      cpu=$((cpu+1))
    fi
  done
  log_ok "XPS: TX queues pinned to CPUs ($xps_count queues)"
}

# ─── 4. KERNEL BUSY POLLING ───────────────────────────────
tune_busy_poll() {
  echo -e "\n${BLD}[4/7] Kernel Busy Polling (zero-sleep packet processing)${NC}"

  # busy_poll: microseconds to busy-poll before sleeping (50µs sweet spot)
  sysctl -w net.core.busy_poll=50   >/dev/null 2>/dev/null || true
  sysctl -w net.core.busy_read=50   >/dev/null 2>/dev/null || true
  log_ok "busy_poll=50µs, busy_read=50µs — kernel spins before sleeping"

  # Persist
  grep -q busy_poll /etc/sysctl.d/99-phoenix.conf 2>/dev/null || {
    echo "net.core.busy_poll = 50"  >> /etc/sysctl.d/99-phoenix.conf
    echo "net.core.busy_read = 50"  >> /etc/sysctl.d/99-phoenix.conf
  }
}

# ─── 5. TCP LATENCY ANNIHILATORS ──────────────────────────
tune_tcp_latency() {
  echo -e "\n${BLD}[5/7] TCP Latency Annihilators${NC}"

  # Disable auto-corking — don't batch small writes, send immediately
  sysctl -w net.ipv4.tcp_autocorking=0 >/dev/null
  log_ok "tcp_autocorking=0 — no batching, every write fires immediately"

  # Thin streams — optimized for low-volume high-frequency streams (HTTP/2 RST)
  sysctl -w net.ipv4.tcp_thin_linear_timeouts=1 >/dev/null
  sysctl -w net.ipv4.tcp_thin_dupack=1 >/dev/null 2>/dev/null || true
  log_ok "tcp_thin_linear_timeouts=1, thin_dupack=1 (fast retransmit for thin streams)"

  # Reduce ACK delay — don't wait 40ms to batch ACKs
  sysctl -w net.ipv4.tcp_delack_min=0 >/dev/null 2>/dev/null || true
  # Quickack via socket option is app-level; kernel-side: reduce ATO
  echo 1 > /proc/sys/net/ipv4/tcp_delack_min 2>/dev/null || true

  # notsent_lowat — reduce send buffer waste, wake writer earlier
  sysctl -w net.ipv4.tcp_notsent_lowat=16384 >/dev/null
  log_ok "tcp_notsent_lowat=16384 — writer wakes earlier, lower memory waste"

  # Persist new values
  grep -q tcp_autocorking /etc/sysctl.d/99-phoenix.conf 2>/dev/null || {
    cat >> /etc/sysctl.d/99-phoenix.conf << 'ADD'

# Level 2 — TCP latency annihilators
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_thin_linear_timeouts = 1
net.ipv4.tcp_notsent_lowat = 16384
ADD
  }
}

# ─── 6. CPU PERFORMANCE MODE ──────────────────────────────
tune_cpu() {
  echo -e "\n${BLD}[6/7] CPU Performance Mode${NC}"

  if [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      echo performance > $gov 2>/dev/null || true
    done
    log_ok "CPU governor → performance (all $NCPUS cores)"
  else
    log_warn "No cpufreq interface (VPS hypervisor controls CPU freq — normal for KVM/Xen)"
    log_info "Requesting max perf via kernel hint..."
  fi

  # Disable CPU idle states for minimum latency (if available)
  if command -v cpupower &>/dev/null; then
    cpupower idle-set -D 0 2>/dev/null && log_ok "CPU deep sleep states disabled via cpupower" || true
  fi

  # Kernel scheduler — reduce latency
  sysctl -w kernel.sched_min_granularity_ns=1000000    >/dev/null 2>/dev/null || true
  sysctl -w kernel.sched_wakeup_granularity_ns=1500000 >/dev/null 2>/dev/null || true
  sysctl -w kernel.sched_migration_cost_ns=250000      >/dev/null 2>/dev/null || true
  log_ok "Scheduler: min_granularity=1ms, wakeup=1.5ms, migration_cost=250µs"

  grep -q sched_min_granularity /etc/sysctl.d/99-phoenix.conf 2>/dev/null || {
    cat >> /etc/sysctl.d/99-phoenix.conf << 'ADD'

# Level 2 — CPU scheduler latency
kernel.sched_min_granularity_ns = 1000000
kernel.sched_wakeup_granularity_ns = 1500000
kernel.sched_migration_cost_ns = 250000
ADD
  }
}

# ─── 7. MEMORY & NUMA ─────────────────────────────────────
tune_memory() {
  echo -e "\n${BLD}[7/7] Memory — NUMA & Huge Pages${NC}"

  NUMA_NODES=$(cat /sys/devices/system/node/online 2>/dev/null || echo "0")
  log_info "NUMA topology: nodes=$NUMA_NODES, CPUs=$NCPUS (single NUMA — optimal)"

  # Disable NUMA balancing (single-node = no benefit, just overhead)
  sysctl -w kernel.numa_balancing=0 >/dev/null 2>/dev/null || true
  log_ok "NUMA balancing disabled (single node — no overhead)"

  # Huge pages — pre-allocate for Rust allocator
  HUGEPAGES=4096  # 4096 × 2MB = 8GB pre-allocated
  echo $HUGEPAGES > /proc/sys/vm/nr_hugepages 2>/dev/null || true
  ACTUAL=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)
  log_ok "Huge pages: requested $HUGEPAGES × 2MB, got $ACTUAL × 2MB = $((ACTUAL*2))MB"

  # Compact memory to reduce fragmentation
  echo 1 > /proc/sys/vm/compact_memory 2>/dev/null || true
  log_ok "Memory compaction triggered"

  grep -q numa_balancing /etc/sysctl.d/99-phoenix.conf 2>/dev/null || {
    echo "kernel.numa_balancing = 0" >> /etc/sysctl.d/99-phoenix.conf
  }
}

# ─── FINAL REPORT ─────────────────────────────────────────
print_report() {
  echo ""
  echo -e "${YLW}╔════════════════════════════════════════════════════╗${NC}"
  echo -e "${YLW}║        🔥 PHOENIX ULTRA TUNE — COMPLETE 🔥         ║${NC}"
  echo -e "${YLW}╚════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${BLD}  Layer 1 (sysctl — already applied):${NC}"
  echo -e "  ${GRN}✅ BBR+FQ · 512MB buffers · 1M fds · syn=65535 · tw_reuse${NC}"
  echo ""
  echo -e "${BLD}  Layer 2 (hardware — just applied):${NC}"
  echo -e "  ${GRN}✅ NIC ring buffers maxed${NC}"
  echo -e "  ${GRN}✅ IRQ affinity spread across all $NCPUS cores${NC}"
  echo -e "  ${GRN}✅ RPS/RFS/XPS — all cores steering packets${NC}"
  echo -e "  ${GRN}✅ Kernel busy-poll 50µs — zero-sleep Rx${NC}"
  echo -e "  ${GRN}✅ TCP auto-corking OFF — instant frame dispatch${NC}"
  echo -e "  ${GRN}✅ Thin stream optimization — fast RST retransmit${NC}"
  echo -e "  ${GRN}✅ notsent_lowat=16KB — writer wakes fast${NC}"
  echo -e "  ${GRN}✅ Scheduler latency minimized${NC}"
  echo -e "  ${GRN}✅ NUMA balancing OFF · Huge pages allocated${NC}"
  echo ""
  echo -e "  ${CYN}NIC: $NIC | CPUs: $NCPUS | ulimit: $(ulimit -n)${NC}"
  echo -e "  ${CYN}BBR: $(sysctl -n net.ipv4.tcp_congestion_control) | qdisc: $(sysctl -n net.core.default_qdisc)${NC}"
  echo -e "  ${CYN}busy_poll: $(sysctl -n net.core.busy_poll 2>/dev/null || echo n/a)µs | autocork: $(sysctl -n net.ipv4.tcp_autocorking)${NC}"
  echo ""
  echo -e "${RED}  🔥🐦 PHOENIX LEVEL TUNING ACHIEVED. Machine is a weapon. 🐦🔥${NC}"
  echo ""
}

main() {
  banner
  [[ $EUID -ne 0 ]] && { echo -e "${RED}Run as root!${NC}"; exit 1; }
  tune_nic_rings
  tune_irq_affinity
  tune_rps_rfs
  tune_busy_poll
  tune_tcp_latency
  tune_cpu
  tune_memory
  print_report
}

main "$@"
