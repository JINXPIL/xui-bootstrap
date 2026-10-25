# shellcheck shell=bash
# lib/system.sh — сетевой стек: BBR, NTP и хардениг sysctl (в т.ч. под нагрузку/флуд).

system_tune() {
  timedatectl set-ntp true 2>/dev/null || warn "NTP не включился — Reality чувствителен к времени"

  local f=/etc/sysctl.d/99-xui.conf
  {
    echo "# создано xui-bootstrap"
    if is_true "${ENABLE_BBR:-1}"; then
      echo "net.core.default_qdisc=fq"
      echo "net.ipv4.tcp_congestion_control=bbr"
    fi
    cat <<'EOF'
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0

# --- устойчивость к SYN-флуду и всплескам соединений ---
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=3
net.core.somaxconn=8192
net.core.netdev_max_backlog=16384
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1

# --- анти-спуфинг и мусорный ICMP ---
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0

# --- ёмкость conntrack (много одновременных прокси-сессий) ---
net.netfilter.nf_conntrack_max=262144
net.ipv4.ip_local_port_range=1024 65535

# --- буферы под высокую пропускную способность ---
net.core.rmem_max=26214400
net.core.wmem_max=26214400
net.ipv4.tcp_rmem=4096 87380 26214400
net.ipv4.tcp_wmem=4096 65536 26214400
EOF
  } >"$f"

  # применяем; часть ключей может отсутствовать до загрузки модулей — не падаем
  modprobe nf_conntrack 2>/dev/null || true
  if is_true "${ENABLE_BBR:-1}"; then modprobe tcp_bbr 2>/dev/null || true; fi
  sysctl -q --system >/dev/null 2>&1 || warn "sysctl применился не полностью (часть ключей недоступна в этом ядре)"

  # проверим, что BBR действительно активен
  if is_true "${ENABLE_BBR:-1}"; then
    local cc; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
    [[ $cc == bbr ]] && ok "Сетевой стек: BBR + fq, хардениг применён" || warn "BBR не активировался (текущий: $cc)"
  else
    ok "Сетевой стек: хардениг применён (BBR отключён)"
  fi
}
