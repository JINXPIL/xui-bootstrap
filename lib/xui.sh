# shellcheck shell=bash
# lib/xui.sh — установка/обновление 3x-ui и доступ к его локальному API.
# Экспортирует: xui_install, xui_bind_panel, api(), а также TOKEN/BASE/PANEL_PORT.

XUI_BIN=${XUI_BIN:-/usr/local/x-ui/x-ui}
XUI_INSTALL_URL=${XUI_INSTALL_URL:-https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh}

# xui_install — ставит или обновляет 3x-ui до нужной версии (неинтерактивно).
xui_install() {
  local ver="${XUI_VERSION:-}"
  if [[ -x $XUI_BIN ]]; then
    info "Обновляю установленный 3x-ui${ver:+ до $ver}…"
  else
    info "Ставлю 3x-ui ${ver:-latest}…"
  fi
  local tmp; tmp=$(mktemp)
  curl -fsSL "$XUI_INSTALL_URL" -o "$tmp" || die "Не скачал install.sh 3x-ui"
  # install.sh 3x-ui уважает эти переменные в неинтерактивном режиме
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none bash "$tmp" ${ver:+"$ver"} </dev/null \
    || die "Установщик 3x-ui завершился с ошибкой"
  rm -f "$tmp"
  [[ -x $XUI_BIN ]] || die "Бинарник x-ui не найден после установки"
}

# xui_bind_panel — прибивает панель к нужному интерфейсу и поднимает API-токен.
# Выставляет глобальные TOKEN, BASE, PANEL_PORT, PANEL_SCHEME, WBP.
xui_bind_panel() {
  if is_true "${PANEL_PUBLIC:-0}"; then
    "$XUI_BIN" setting -listenIP 0.0.0.0 >/dev/null || warn "Не смог открыть панель наружу"
  else
    "$XUI_BIN" setting -listenIP 127.0.0.1 >/dev/null || warn "Не смог прибить панель к localhost"
  fi

  TOKEN=$("$XUI_BIN" setting -getApiToken -tokenName xui-bootstrap 2>/dev/null | awk '/^apiToken:/{print $2}' || true)
  [[ -n $TOKEN ]] || die "x-ui не выдал API-токен (нужна актуальная версия 3x-ui с поддержкой API-токенов)"

  xui_panel_ssl   # самоподписанный HTTPS для панели (бессрочно)
  systemctl restart x-ui

  local show; show=$("$XUI_BIN" setting -show)
  PANEL_PORT=$(awk '$1=="port:"{print $2}' <<<"$show")
  WBP=$(awk '$1=="webBasePath:"{print $2}' <<<"$show"); WBP="/${WBP#/}"; WBP="${WBP%/}/"
  [[ -n $PANEL_PORT ]] || die "Не смог определить порт панели из 'x-ui setting -show'"

  # Схему НЕ угадываем по слову «SSL» в выводе (там оно есть и при выключенном
  # TLS). Пробуем http и https напрямую, каждую секунду, пока API не ответит.
  local _ sc
  for _ in $(seq 1 60); do
    for sc in http https; do
      BASE="$sc://127.0.0.1:$PANEL_PORT$WBP"
      if api GET panel/api/server/status 2>/dev/null | jq -e '.success' >/dev/null 2>&1; then
        # shellcheck disable=SC2034  # PANEL_SCHEME/XUI_API_READY читаются в bootstrap.sh/keys.sh/inbounds.sh
        PANEL_SCHEME="$sc"
        # shellcheck disable=SC2034
        XUI_API_READY=1
        ok "API панели отвечает ($sc, порт $PANEL_PORT)"
        return 0
      fi
    done
    sleep 1
  done
  warn "Последние строки журнала x-ui:"
  journalctl -u x-ui -n 15 --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
  die "API панели не ответило за 60с (порт $PANEL_PORT, путь $WBP)"
}

# xui_panel_ssl — включает HTTPS для панели самоподписанным сертификатом.
# Он бессрочный (10 лет), не имеет 6-дневного лимита Let's Encrypt-для-IP и
# работает без домена. Браузер один раз предупредит про самоподпись — это ок,
# трафик и пароль всё равно шифруются. Отключается через PANEL_SSL=0.
xui_panel_ssl() {
  is_true "${PANEL_SSL:-1}" || { info "HTTPS панели отключён (PANEL_SSL=0)"; return 0; }
  local dir="${CERT_DIR:-/etc/x-ui-bootstrap}"
  local pub="$dir/panel.pem" key="$dir/panel.key"
  install -d -m 700 "$dir"

  if [[ ! -s $pub || ! -s $key ]]; then
    info "Генерирую бессрочный самоподписанный сертификат для панели…"
    local host="${PUBLIC_HOST:-${SERVER_IP:-127.0.0.1}}" san
    if [[ $host =~ ^[0-9.]+$ ]]; then san="IP:$host"; else san="DNS:$host"; fi
    [[ -n ${SERVER_IP:-} && $SERVER_IP != "$host" ]] && san="$san,IP:$SERVER_IP"
    openssl ecparam -genkey -name prime256v1 -out "$key" 2>/dev/null
    if ! openssl req -new -x509 -key "$key" -out "$pub" -days 3650 \
         -subj "/CN=$host" -addext "subjectAltName=$san" 2>/dev/null; then
      warn "Не смог создать сертификат панели — останется HTTP"; return 0
    fi
    chmod 644 "$pub"; chmod 600 "$key"
  fi

  if "$XUI_BIN" setting -webCert "$pub" -webCertKey "$key" >/dev/null 2>&1; then
    ok "Панель: самоподписанный HTTPS включён (сертификат бессрочный)"
  else
    warn "Панель не приняла сертификат — останется HTTP"
  fi
}

# api METHOD PATH [curl-args...] — вызов локального API панели.
api() {
  local m=$1 p=$2; shift 2
  curl -k -sS --max-time 180 -X "$m" -H "Authorization: Bearer ${TOKEN:-}" "$@" "$BASE$p"
}

# xui_install_xray VERSION — фиксирует версию ядра Xray, если задана.
xui_install_xray() {
  local ver="${1:-}"
  [[ -n $ver ]] || return 0
  if api POST "panel/api/server/installXray/$ver" | jq -e '.success' >/dev/null; then
    ok "Xray → $ver"
  else
    warn "Не удалось поставить Xray $ver — оставляю текущую версию ядра"
  fi
}

# xui_credentials — печатает "USER PASS" из install-result, если доступно.
xui_credentials() {
  local u='' p=''
  if [[ -r /etc/x-ui/install-result.env ]]; then
    # shellcheck source=/dev/null
    u=$(. /etc/x-ui/install-result.env; printf '%s' "${XUI_USERNAME:-}")
    # shellcheck source=/dev/null
    p=$(. /etc/x-ui/install-result.env; printf '%s' "${XUI_PASSWORD:-}")
  fi
  printf '%s\t%s' "$u" "$p"
}

# xui_xray_version — версия ядра Xray для отчёта.
xui_xray_version() {
  # бинарник ядра имеет суффикс архитектуры (xray-linux-amd64 и т.п.)
  # shellcheck disable=SC2211
  { /usr/local/x-ui/bin/xray-linux-* version 2>/dev/null || true; } | awk 'NR==1{print $2}'
}
