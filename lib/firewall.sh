# shellcheck shell=bash
# lib/firewall.sh — базовый UFW, анти-DDoS на nftables и установка демона
# xui-fw-sync, который держит фаервол в согласии с панелью (лечит «таймауты»
# у инбаундов, добавленных вручную уже после установки).

FW_STATE_DIR=${FW_STATE_DIR:-/etc/x-ui-bootstrap}
NFT_DDOS=/etc/nftables.d/xui-ddos.nft

# firewall_base SSH_PORTS[] — базовая политика UFW + SSH + служебные порты.
firewall_base() {
  local -n _ssh=$1
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  local p
  for p in "${_ssh[@]}"; do ufw allow "$p/tcp" comment 'xui-ssh' >/dev/null; done
  ufw allow 2096/tcp comment 'xui-sub' >/dev/null 2>&1 || true
  if [[ ${MASK_MODE:-} == selfsteal ]]; then ufw allow 80/tcp comment 'xui-acme' >/dev/null; fi
}

# firewall_open_ports TCP_CSV UDP_CSV — открыть порты инбаундов (через запятую).
firewall_open_ports() {
  local tcp="$1" udp="$2" p
  IFS=', ' read -ra _t <<<"$tcp"
  IFS=', ' read -ra _u <<<"$udp"
  for p in "${_t[@]}" ${EXTRA_TCP_PORTS:-}; do [[ -n $p ]] && ufw allow "$p/tcp" comment 'xui-sync' >/dev/null; done
  for p in "${_u[@]}" ${EXTRA_UDP_PORTS:-}; do [[ -n $p ]] && ufw allow "$p/udp" comment 'xui-sync' >/dev/null; done
  if is_true "${PANEL_PUBLIC:-0}" && [[ -n ${PANEL_PORT:-} ]]; then
    ufw allow "$PANEL_PORT/tcp" comment 'xui-panel' >/dev/null 2>&1 || true
  fi
  ufw --force enable >/dev/null
}

# firewall_ddos SSH_PORTS[] — разворачивает nftables-таблицу анти-DDoS.
firewall_ddos() {
  is_true "${ENABLE_DDOS:-1}" || { info "Анти-DDoS отключён (ENABLE_DDOS=0)"; return 0; }
  local -n _ssh=$1
  require nft
  install -d -m 755 /etc/nftables.d

  local guard_ports; guard_ports=$(IFS=,; echo "${_ssh[*]}")
  [[ -n ${PANEL_PORT:-} ]] && guard_ports="$guard_ports, $PANEL_PORT"

  sed -e "s|__SYN_RATE__|${DDOS_SYN_RATE:-2000}|g" \
      -e "s|__SYN_BURST__|${DDOS_SYN_BURST:-3000}|g" \
      -e "s|__ICMP_RATE__|${DDOS_ICMP_RATE:-50}|g" \
      -e "s|__ICMP_BURST__|${DDOS_ICMP_BURST:-100}|g" \
      -e "s|__GUARD_RATE__|${DDOS_GUARD_RATE:-20}|g" \
      -e "s|__GUARD_PORTS__|${guard_ports}|g" \
      "$DIR/nftables/xui-ddos.nft.template" >"$NFT_DDOS"

  if ! nft -c -f "$NFT_DDOS"; then
    warn "nft: конфиг анти-DDoS не прошёл проверку — пропускаю"
    rm -f "$NFT_DDOS"; return 0
  fi
  nft -f "$NFT_DDOS" || { warn "nft: не удалось применить анти-DDoS"; return 0; }

  # автозагрузка таблицы при старте системы (после nftables.service/ufw)
  cat >/etc/systemd/system/xui-ddos.service <<EOF
[Unit]
Description=xui-bootstrap anti-DDoS nftables table
After=network-pre.target nftables.service ufw.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f $NFT_DDOS
ExecReload=/usr/sbin/nft -f $NFT_DDOS
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable xui-ddos.service >/dev/null 2>&1 || true
  ok "Анти-DDoS: nftables-таблица xui_ddos активна (SYN/ICMP-флуд, мусорные пакеты, защита SSH/панели)"
}

# firewall_install_sync — ставит демон синхронизации фаервола с панелью.
firewall_install_sync() {
  install -d -m 700 "$FW_STATE_DIR"
  install -m 700 "$DIR/bin/xui-fw-sync" /usr/local/sbin/xui-fw-sync
  install -m 644 "$DIR/systemd/xui-fw-sync.service" /etc/systemd/system/xui-fw-sync.service
  install -m 644 "$DIR/systemd/xui-fw-sync.timer"   /etc/systemd/system/xui-fw-sync.timer
  systemctl daemon-reload
  systemctl enable --now xui-fw-sync.timer >/dev/null 2>&1 || warn "Не смог включить таймер xui-fw-sync"
  # первый прогон сразу, синхронно
  /usr/local/sbin/xui-fw-sync >/dev/null 2>&1 || true
  ok "Демон xui-fw-sync активен: порты новых инбаундов открываются автоматически (каждые ${FW_SYNC_INTERVAL:-2} мин)"
}
