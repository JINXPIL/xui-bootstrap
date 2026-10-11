# shellcheck shell=bash
# lib/autoupdate.sh — авто-обновление компонентов Xray через systemd-таймеры.
#   • geodata (geoip/geosite) — безопасно, по умолчанию ВКЛ (AUTO_UPDATE_GEODATA=1);
#   • ядро Xray — с проверкой и откатом, по умолчанию ВЫКЛ (AUTO_UPDATE_CORE=0),
#     т.к. авто-апдейт ядра может молча сломать Reality для части клиентов.
# Сам скрипт обновления — bin/xui-update.

autoupdate_install_daemon() {
  local src="$DIR/bin/xui-update" bin=/usr/local/bin/xui-update
  [[ -r $src ]] || { warn "autoupdate: нет $src — пропускаю"; return 0; }
  install -m 755 "$src" "$bin" 2>/dev/null || { warn "autoupdate: не установил xui-update"; return 0; }
  xui_assets_install   # свежие lib/*.sh в /usr/local/share — их читает xui-update

  # --- geodata ---
  cat >/etc/systemd/system/xui-geodata.service <<'EOF'
[Unit]
Description=xui-bootstrap: обновление geodata (geoip/geosite)
After=network-online.target x-ui.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xui-update geodata
EOF
  cat >/etc/systemd/system/xui-geodata.timer <<'EOF'
[Unit]
Description=xui-bootstrap: еженедельное обновление geodata

[Timer]
OnCalendar=Mon 05:30
RandomizedDelaySec=3h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  # --- ядро Xray (с откатом) ---
  cat >/etc/systemd/system/xui-core.service <<'EOF'
[Unit]
Description=xui-bootstrap: обновление ядра Xray (проверка здоровья + откат)
After=network-online.target x-ui.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xui-update core
EOF
  cat >/etc/systemd/system/xui-core.timer <<'EOF'
[Unit]
Description=xui-bootstrap: еженедельное обновление ядра Xray

[Timer]
OnCalendar=Mon 05:45
RandomizedDelaySec=3h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload 2>/dev/null || true

  if is_true "${AUTO_UPDATE_GEODATA:-1}"; then
    systemctl enable --now xui-geodata.timer >/dev/null 2>&1 \
      && ok "Авто-geodata: раз в неделю (вкл)" \
      || warn "Не включил таймер geodata"
  else
    systemctl disable --now xui-geodata.timer >/dev/null 2>&1 || true
    info "Авто-geodata выключено (AUTO_UPDATE_GEODATA=0)"
  fi

  if is_true "${AUTO_UPDATE_CORE:-0}"; then
    systemctl enable --now xui-core.timer >/dev/null 2>&1 \
      && ok "Авто-обновление ядра Xray: раз в неделю (вкл, с откатом)" \
      || warn "Не включил таймер обновления ядра"
    warn "Авто-апдейт ядра может молча сломать Reality для части клиентов — проверяй подключение после обновлений"
  else
    systemctl disable --now xui-core.timer >/dev/null 2>&1 || true
    info "Авто-обновление ядра Xray выключено (AUTO_UPDATE_CORE=0) — безопасный дефолт; включить: AUTO_UPDATE_CORE=1 или 'systemctl enable --now xui-core.timer'"
  fi
}
