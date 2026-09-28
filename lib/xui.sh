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
  systemctl restart x-ui

  local show; show=$("$XUI_BIN" setting -show)
  PANEL_PORT=$(awk '$1=="port:"{print $2}' <<<"$show")
  WBP=$(awk '$1=="webBasePath:"{print $2}' <<<"$show"); WBP="/${WBP#/}"; WBP="${WBP%/}/"
  if grep -qi "SSL" <<<"$show"; then PANEL_SCHEME="https"; else PANEL_SCHEME="http"; fi
  BASE="$PANEL_SCHEME://127.0.0.1:$PANEL_PORT$WBP"

  # ждём, пока API реально ответит
  local _
  for _ in $(seq 1 40); do
    if api GET panel/api/server/status 2>/dev/null | jq -e '.success' >/dev/null 2>&1; then
      # shellcheck disable=SC2034  # читается в keys.sh/inbounds.sh
      XUI_API_READY=1
      ok "API панели отвечает (порт $PANEL_PORT)"
      return 0
    fi
    sleep 1
  done
  die "API панели не ответило за 40с (см. journalctl -u x-ui)"
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
