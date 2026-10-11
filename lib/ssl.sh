# shellcheck shell=bash
# lib/ssl.sh — доверенный сертификат Let's Encrypt через acme.sh.
# Клиенты (FlClash/Happ) отвергают самоподписанные серты, поэтому при
# SSL_MODE=letsencrypt выпускаем валидный сертификат и используем его для панели,
# подписки и QUIC-инбаундов (Hysteria2). Авто-продление — штатным крон/таймером
# acme.sh + reloadcmd (перезапуск x-ui). Экспортирует LE_OK/LE_CERT/LE_KEY/LE_SNI.

# shellcheck disable=SC2034  # LE_OK/LE_CERT/LE_KEY/LE_SNI читаются в xui.sh/inbounds.sh/bootstrap.sh
LE_OK=0; LE_CERT=""; LE_KEY=""; LE_SNI=""

_acme_bin() { printf '%s' "${HOME:-/root}/.acme.sh/acme.sh"; }

_acme_install() {
  local a; a=$(_acme_bin)
  [[ -x $a ]] && return 0
  info "Ставлю acme.sh…"
  curl -fsSL https://get.acme.sh | sh -s -- --nocron >/dev/null 2>&1 || true
  [[ -x $a ]]
}

# _acme_renew_timer — гарантированное фоновое продление (в дополнение к крону acme.sh).
_acme_renew_timer() {
  local a; a=$(_acme_bin)
  cat >/etc/systemd/system/xui-acme-renew.service <<EOF
[Unit]
Description=xui-bootstrap acme.sh renew
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$a --cron --home ${HOME:-/root}/.acme.sh
EOF
  cat >/etc/systemd/system/xui-acme-renew.timer <<'EOF'
[Unit]
Description=Daily acme.sh renew for xui-bootstrap

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now xui-acme-renew.timer >/dev/null 2>&1 || true
}

# ssl_setup — выпускает/подхватывает доверенный сертификат. Безопасный фолбэк на
# самоподписанный при любой неудаче (LE_OK остаётся 0).
ssl_setup() {
  LE_OK=0
  # selfsteal уже выпустил LE-сертификат домена через certbot в mask.sh
  if [[ ${MASK_MODE:-} == selfsteal && -n ${DOMAIN:-} && -s /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then
    LE_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    LE_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    LE_SNI="$DOMAIN"; LE_OK=1
    ok "SSL: использую доверенный сертификат домена $DOMAIN (selfsteal)"
    return 0
  fi

  [[ ${SSL_MODE:-self-signed} == letsencrypt ]] || { info "SSL панели/инбаундов: самоподписанный (SSL_MODE=$SSL_MODE)"; return 0; }
  require curl
  _acme_install || { warn "acme.sh не установился — остаюсь на самоподписанном"; return 0; }

  local id; local profile_args=()
  if [[ -n ${DOMAIN:-} ]]; then
    id="$DOMAIN"
  else
    id="${SERVER_IP:-${SERVER_ADDR:-}}"
    # Let's Encrypt для IP — короткоживущий профиль (~6 дней), авто-продление
    profile_args=(--server letsencrypt --certificate-profile shortlived --days 6)
  fi
  [[ -n $id ]] || { warn "SSL: не определил домен/IP — самоподписанный"; return 0; }

  ufw allow 80/tcp comment 'xui-acme' >/dev/null 2>&1 || true
  local a; a=$(_acme_bin)
  "$a" --set-default-ca --server letsencrypt --force >/dev/null 2>&1 || true
  [[ -n ${ACME_EMAIL:-} ]] && "$a" --register-account -m "$ACME_EMAIL" >/dev/null 2>&1 || true

  info "Выпускаю сертификат Let's Encrypt для $id (нужен свободный порт 80)…"
  if ! "$a" --issue -d "$id" --standalone --httpport 80 "${profile_args[@]}" --force >/dev/null 2>&1; then
    warn "SSL: не удалось выпустить LE-сертификат для $id (порт 80 занят/недоступен, rate-limit?) — самоподписанный"
    return 0
  fi

  install -d -m 700 "${CERT_DIR:-/etc/x-ui-bootstrap}"
  LE_CERT="${CERT_DIR:-/etc/x-ui-bootstrap}/le-fullchain.pem"
  LE_KEY="${CERT_DIR:-/etc/x-ui-bootstrap}/le-privkey.pem"
  # installcert может вернуть ненулевой код из-за reloadcmd — проверяем файлы, а не код
  "$a" --installcert --force -d "$id" \
    --key-file "$LE_KEY" --fullchain-file "$LE_CERT" \
    --reloadcmd "systemctl restart x-ui; systemctl reload nginx 2>/dev/null || true" >/dev/null 2>&1 || true
  if [[ ! -s $LE_CERT || ! -s $LE_KEY ]]; then
    warn "SSL: файлы сертификата не появились — самоподписанный"; return 0
  fi
  chmod 600 "$LE_KEY"; chmod 644 "$LE_CERT"
  "$a" --upgrade --auto-upgrade >/dev/null 2>&1 || true
  _acme_renew_timer

  LE_OK=1; LE_SNI="$id"
  ok "SSL: доверенный Let's Encrypt для $id ($([[ -n ${DOMAIN:-} ]] && echo '90 дней' || echo 'IP shortlived ~6д')), авто-продление включено"
}
