# shellcheck shell=bash
# lib/ssl.sh — доверенный сертификат Let's Encrypt через acme.sh.
# Клиенты (FlClash/Happ) отвергают самоподписанные серты, поэтому при
# SSL_MODE=letsencrypt выпускаем валидный сертификат и используем его для панели,
# подписки и QUIC-инбаундов (Hysteria2). Авто-продление — таймер xui-acme-renew +
# reloadcmd (SIGHUP панели, БЕЗ рестарта xray). Экспортирует LE_OK/LE_CERT/LE_KEY/LE_SNI.

# shellcheck disable=SC2034  # LE_OK/LE_CERT/LE_KEY/LE_SNI читаются в xui.sh/inbounds.sh/bootstrap.sh
LE_OK=0; LE_CERT=""; LE_KEY=""; LE_SNI=""

_acme_bin() { printf '%s' "${HOME:-/root}/.acme.sh/acme.sh"; }

# После продления: SIGHUP ТОЛЬКО главному процессу x-ui — панель и подписка
# перечитывают сертификат, а xray не перезапускается (клиенты не рвутся).
# TLS-инбаунды xray (Hysteria2) сами перечитывают файл серта раз в час
# (при ocspStapling: 0 — штатный интервал 3600 с, проверено по исходникам Xray).
# Нельзя `systemctl kill -s HUP x-ui`: сигнал уйдёт и дочернему xray, а Go-процесс
# без обработчика SIGHUP от него завершается. Нельзя и `kill -HUP 0` (при
# MainPID=0) — это сигнал всей группе процессов. acme.sh исполняет строку через sh.
# shellcheck disable=SC2016  # $(...) должен раскрыться в момент продления, не сейчас
XUI_ACME_RELOADCMD='p=$(systemctl show -p MainPID --value x-ui 2>/dev/null); if [ "${p:-0}" -gt 0 ] 2>/dev/null; then kill -HUP "$p"; else systemctl restart x-ui; fi; systemctl reload nginx 2>/dev/null || true'
# Через сколько дней продлевать (acme.sh продлевает за сутки до этого срока):
#  • IP (shortlived, живёт ~6,7 сут) — на ~3-и сутки: несколько суточных попыток
#    в запасе и ≈2 выпуска в неделю (лимит LE — 5 в неделю на набор имён);
#  • домен — раз в ~месяц, с запасом на сокращение сроков LE до 45 дней.
XUI_ACME_DAYS_IP=4
XUI_ACME_DAYS_DOMAIN=30

# _acme_conf ID — путь к конфигу домена/IP в acme.sh (ECC-ключи лежат в ID_ecc/).
_acme_conf() {
  local id=$1 h="${HOME:-/root}/.acme.sh" d
  for d in "$h/${id}_ecc" "$h/$id"; do
    [[ -r $d/$id.conf ]] && { printf '%s' "$d/$id.conf"; return 0; }
  done
  return 1
}

# _acme_tune_renewal ID DAYS — выставляет интервал продления уже выпущенному
# сертификату (Le_RenewalDays) и пересчитывает ближайшую дату продления.
_acme_tune_renewal() {
  local conf; conf=$(_acme_conf "$1") || return 1
  python3 -I - "$conf" "$2" <<'PY'
import re, sys
path, days = sys.argv[1], int(sys.argv[2])
s = open(path, encoding="utf-8").read()
def setk(text, key, val):
    line = f"{key}='{val}'"
    if re.search(rf"^{key}=", text, flags=re.M):
        return re.sub(rf"^{key}=.*$", line, text, flags=re.M)
    return text.rstrip("\n") + "\n" + line + "\n"
s = setk(s, "Le_RenewalDays", days)
m = re.search(r"^Le_CertCreateTime='?(\d+)'?", s, flags=re.M)
if m:
    s = setk(s, "Le_NextRenewTime", int(m.group(1)) + days * 86400 - 86400)
open(path, "w", encoding="utf-8").write(s)
PY
}

# _le_cert_reusable FILE ID — серт есть, покрывает ID и живёт ещё > 48 ч.
_le_cert_reusable() {
  local f=$1 id=$2
  [[ -s $f ]] || return 1
  openssl x509 -in "$f" -noout -checkend 172800 >/dev/null 2>&1 || return 1
  openssl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null | grep -qF "$id"
}

# _ssl_rescue ID CONF — серт истёк или истекает меньше чем через 48 ч, значит
# плановое продление не срабатывает (IP-серт живёт ~6,7 сут, запас маленький).
# Продлеваем принудительно; если не вышло — печатаем причину из лога acme.sh.
_ssl_rescue() {
  local id=$1 conf=$2 d="${CERT_DIR:-/etc/x-ui-bootstrap}" a log ecc=()
  local f="$d/le-fullchain.pem"
  a=$(_acme_bin)
  [[ $conf == *_ecc/* ]] && ecc=(--ecc)
  if openssl x509 -in "$f" -noout -checkend 0 >/dev/null 2>&1; then
    warn "SSL $id: сертификат истекает меньше чем через 48 ч — плановое продление не сработало, продлеваю принудительно…"
  else
    warn "SSL $id: сертификат ИСТЁК — Hysteria2/TUIC/WS-TLS и обновление подписки не работают. Продлеваю принудительно…"
  fi
  # HTTP-01 standalone: Let's Encrypt должен достучаться до порта 80
  command -v ufw >/dev/null 2>&1 && ufw allow 80/tcp comment 'xui-acme' >/dev/null 2>&1 || true
  log="$d/acme-renew.log"
  if "$a" --renew -d "$id" "${ecc[@]}" --force >"$log" 2>&1 \
     && openssl x509 -in "$f" -noout -checkend 172800 >/dev/null 2>&1; then
    ok "SSL $id: продлён, новый сертификат до $(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)"
    return 0
  fi
  warn "SSL $id: продлить не удалось. Из лога acme.sh ($log):"
  grep -iE 'error|invalid|timeout|refused|rate.?limit|unauthorized|connection|socat|denied' "$log" 2>/dev/null \
    | tail -n 5 | sed 's/^/    /' >&2 || true
  warn "Частые причины: порт 80 закрыт у хостера или занят (ss -ltnp 'sport = :80'), лимит Let's Encrypt. Исправь и запусти снова: bash update-tools.sh"
  return 1
}

# ssl_refresh_renewal — для УЖЕ выпущенного серта: новый reloadcmd (без рестарта
# xray), интервал продления и таймер. Базу панели не трогает. Для update-tools.sh.
ssl_refresh_renewal() {
  local f="${CERT_DIR:-/etc/x-ui-bootstrap}/le-fullchain.pem" k="${CERT_DIR:-/etc/x-ui-bootstrap}/le-privkey.pem"
  local a; a=$(_acme_bin)
  [[ -s $f && -x $a ]] || { info "SSL: сертификата Let's Encrypt от xui-bootstrap нет — пропускаю"; return 0; }
  local id days conf
  id=$(openssl x509 -in "$f" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' \
       | sed -n 's/^[[:space:]]*\(IP Address\|DNS\):[[:space:]]*//p' | head -n1)
  [[ -n $id ]] || { warn "SSL: не определил, на что выпущен сертификат"; return 0; }
  conf=$(_acme_conf "$id") || { warn "SSL: acme.sh не знает про $id — продление не настроено"; return 0; }
  if [[ $id =~ ^[0-9.:]+$ ]]; then days=$XUI_ACME_DAYS_IP; else days=$XUI_ACME_DAYS_DOMAIN; fi
  "$a" --installcert -d "$id" --key-file "$k" --fullchain-file "$f" \
    --reloadcmd "$XUI_ACME_RELOADCMD" >/dev/null 2>&1 || true
  _acme_tune_renewal "$id" "$days" || true
  _acme_renew_timer
  openssl x509 -in "$f" -noout -checkend 172800 >/dev/null 2>&1 || _ssl_rescue "$id" "$conf" || true
  local nxt; nxt=$(sed -n "s/^Le_NextRenewTime='\{0,1\}\([0-9]*\).*/\1/p" "$conf" 2>/dev/null)
  ok "SSL $id: продление каждые ~$((days - 1)) сут без рестарта xray${nxt:+, ближайшее — $(date -u -d "@$nxt" '+%F %H:%M UTC')}; серт до $(openssl x509 -in "$f" -noout -enddate | cut -d= -f2)"
}

_acme_install() {
  local a; a=$(_acme_bin)
  [[ -x $a ]] && return 0
  info "Ставлю acme.sh…"
  curl -fsSL https://get.acme.sh | sh -s -- --nocron >/dev/null 2>&1 || true
  [[ -x $a ]]
}

# _acme_renew_timer — гарантированное фоновое продление (в дополнение к крону acme.sh).
_acme_renew_timer() {
  local a sd=${SYSTEMD_DIR:-/etc/systemd/system}; a=$(_acme_bin)
  # ExecStartPre: правило для порта 80 могли удалить вручную — без него
  # HTTP-01 не пройдёт, и IP-серт (живёт ~6,7 сут) истечёт молча
  cat >"$sd/xui-acme-renew.service" <<EOF
[Unit]
Description=xui-bootstrap acme.sh renew
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStartPre=-/bin/sh -c 'command -v ufw >/dev/null && ufw allow 80/tcp comment xui-acme >/dev/null; exit 0'
ExecStart=$a --cron --home ${HOME:-/root}/.acme.sh
EOF
  cat >"$sd/xui-acme-renew.timer" <<'EOF'
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
    profile_args=(--server letsencrypt --certificate-profile shortlived --days "$XUI_ACME_DAYS_IP")
  fi
  [[ -n $id ]] || { warn "SSL: не определил домен/IP — самоподписанный"; return 0; }
  [[ -n ${DOMAIN:-} ]] && profile_args=(--days "$XUI_ACME_DAYS_DOMAIN")

  # Повторный запуск: действующий серт не перевыпускаем (лимиты LE), только
  # обновляем настройки продления.
  LE_CERT="${CERT_DIR:-/etc/x-ui-bootstrap}/le-fullchain.pem"
  LE_KEY="${CERT_DIR:-/etc/x-ui-bootstrap}/le-privkey.pem"
  if _le_cert_reusable "$LE_CERT" "$id" && [[ -s $LE_KEY ]] && _acme_conf "$id" >/dev/null; then
    LE_OK=1; LE_SNI="$id"
    ssl_refresh_renewal
    return 0
  fi

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
  # installcert может вернуть ненулевой код из-за reloadcmd — проверяем файлы, а не код
  "$a" --installcert --force -d "$id" \
    --key-file "$LE_KEY" --fullchain-file "$LE_CERT" \
    --reloadcmd "$XUI_ACME_RELOADCMD" >/dev/null 2>&1 || true
  if [[ ! -s $LE_CERT || ! -s $LE_KEY ]]; then
    warn "SSL: файлы сертификата не появились — самоподписанный"; return 0
  fi
  chmod 600 "$LE_KEY"; chmod 644 "$LE_CERT"
  "$a" --upgrade --auto-upgrade >/dev/null 2>&1 || true
  _acme_renew_timer

  LE_OK=1; LE_SNI="$id"
  ok "SSL: доверенный Let's Encrypt для $id ($([[ -n ${DOMAIN:-} ]] && echo '90 дней' || echo 'IP shortlived ~6д')), авто-продление включено"
}
